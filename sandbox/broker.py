"""ToolBroker: the ONLY way an agent can touch files, the network, programs or email.

Every call goes through the same pipeline:
  budget -> tool granted? -> argument schema -> capability check -> human approval -> run -> audit
Deny by default: if anything is missing or unclear, the call is refused with a clear reason
(which can be shown to the model so it can choose another approach).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .checks import Resolver, check_command, check_path, check_recipient, check_url, resolve_host
from .docker import docker_argv
from .policy import Policy
from .redact import redact


# ----------------------------------------------------------- argument schemas
class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PathArgs(_Args):
    path: str = Field(min_length=1, max_length=500)


class WriteArgs(_Args):
    path: str = Field(min_length=1, max_length=500)
    content: str


class HttpArgs(_Args):
    url: str = Field(min_length=1, max_length=2000)


class CommandArgs(_Args):
    command: str = Field(min_length=1, max_length=50)
    args: list[str] = Field(default_factory=list, max_length=20)


class EmailArgs(_Args):
    to: str = Field(min_length=3, max_length=200)
    subject: str = Field(max_length=200)
    body: str


ARG_MODELS: dict[str, type[_Args]] = {
    "read_file": PathArgs, "list_dir": PathArgs, "write_file": WriteArgs,
    "http_get": HttpArgs, "run_command": CommandArgs, "send_email": EmailArgs,
}


@dataclass
class ToolResult:
    ok: bool
    output: str = ""
    denied: str | None = None  # policy said no
    error: str | None = None  # allowed, but the tool itself failed

    def for_model(self) -> str:
        if self.denied:
            return f"DENIED by policy: {self.denied}"
        if self.error:
            return f"ERROR: {self.error}"
        return self.output


class Denied(Exception):
    pass


Approver = Callable[[str, dict], bool]


class ToolBroker:
    def __init__(self, policy: Policy, base_dir: Path | None = None, approver: Approver | None = None,
                 audit_path: Path | None = None, resolver: Resolver = resolve_host,
                 http_transport: httpx.BaseTransport | None = None, use_docker: bool = False):
        self.policy = policy
        self.root = policy.root_path(base_dir)
        self.approver = approver
        self.audit_path = audit_path
        self.resolver = resolver
        self.http_transport = http_transport
        self.use_docker = use_docker
        self.calls = Counter()
        self.outbox: list[dict] = []  # send_email is simulated: messages land here

    # ------------------------------------------------------------- pipeline
    def call(self, tool: str, args: dict) -> ToolResult:
        start = time.perf_counter()
        try:
            cap, parsed = self._authorize(tool, args)
        except Denied as exc:
            result = ToolResult(False, denied=str(exc))
        else:
            self.calls[tool] += 1
            self.calls["__total__"] += 1
            try:
                result = ToolResult(True, getattr(self, f"_run_{tool}")(cap, parsed))
            except Denied as exc:  # e.g. a redirect to a forbidden host
                result = ToolResult(False, denied=str(exc))
            except Exception as exc:  # the tool failed, not the policy
                result = ToolResult(False, error=f"{type(exc).__name__}: {exc}"[:300])
        self._audit(tool, args, result, time.perf_counter() - start)
        return result

    def _authorize(self, tool: str, args: dict):
        b = self.policy.budgets
        if self.calls["__total__"] >= b.max_calls:
            raise Denied(f"call budget exhausted ({b.max_calls} calls)")
        if tool in b.per_tool and self.calls[tool] >= b.per_tool[tool]:
            raise Denied(f"budget for {tool} exhausted ({b.per_tool[tool]} calls)")
        cap = getattr(self.policy.tools, tool, None) if tool in ARG_MODELS else None
        if cap is None:
            raise Denied(f"tool {tool!r} is not granted to agent {self.policy.agent!r}")
        try:
            parsed = ARG_MODELS[tool].model_validate(args)
        except ValidationError as exc:
            raise Denied(f"bad arguments: {exc.errors()[0]['loc']} {exc.errors()[0]['msg']}") from exc

        reason = None
        if tool in ("read_file", "list_dir", "write_file"):
            _, reason = check_path(self.root, parsed.path, cap.paths)
            if not reason and tool == "write_file" and len(parsed.content.encode()) > cap.max_bytes:
                reason = f"content larger than {cap.max_bytes} bytes"
        elif tool == "http_get":
            reason = check_url(parsed.url, cap.domains, self.resolver)
        elif tool == "run_command":
            reason = check_command(parsed.command, parsed.args, cap.commands)
        elif tool == "send_email":
            reason = check_recipient(parsed.to, cap.recipients)
            if not reason and len(parsed.body) > cap.max_body:
                reason = "email body too long"
        if reason:
            raise Denied(reason)

        if cap.require_approval:
            if self.approver is None:
                raise Denied(f"{tool} needs human approval and no approver is available")
            if not self.approver(tool, redact(parsed.model_dump())):
                raise Denied("a human reviewer rejected this action")
        return cap, parsed

    # ---------------------------------------------------------------- tools
    def _run_read_file(self, cap, a: PathArgs) -> str:
        target, _ = check_path(self.root, a.path, cap.paths)
        if not target.is_file():
            raise FileNotFoundError(a.path)
        if target.stat().st_size > cap.max_bytes:
            raise ValueError(f"file larger than {cap.max_bytes} bytes")
        return target.read_text(encoding="utf-8", errors="replace")

    def _run_list_dir(self, cap, a: PathArgs) -> str:
        target, _ = check_path(self.root, a.path, cap.paths)
        return "\n".join(sorted(p.name + ("/" if p.is_dir() else "") for p in target.iterdir()))

    def _run_write_file(self, cap, a: WriteArgs) -> str:
        target, _ = check_path(self.root, a.path, cap.paths)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(a.content, encoding="utf-8")
        return f"wrote {len(a.content)} characters to {a.path}"

    def _run_http_get(self, cap, a: HttpArgs) -> str:
        url = a.url
        with httpx.Client(transport=self.http_transport, timeout=cap.timeout_s, follow_redirects=False) as client:
            for _ in range(cap.max_redirects + 1):
                with client.stream("GET", url) as r:
                    if r.is_redirect:
                        nxt = urljoin(url, r.headers.get("location", ""))
                        reason = check_url(nxt, cap.domains, self.resolver)  # re-check EVERY hop
                        if reason:
                            raise Denied(f"redirect blocked: {reason}")
                        url = nxt
                        continue
                    body = b""
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > cap.max_bytes:
                            raise ValueError(f"response larger than {cap.max_bytes} bytes")
                    return f"HTTP {r.status_code}\n{body.decode('utf-8', 'replace')}"
        raise ValueError("too many redirects")

    def _run_run_command(self, cap, a: CommandArgs) -> str:
        exe = sys.executable if a.command == "python" else shutil.which(a.command)
        if not exe:
            raise FileNotFoundError(a.command)
        argv = [exe, *a.args]
        if self.use_docker:  # strong isolation: no network, read-only FS, no capabilities, limits
            argv = docker_argv(a.command, a.args, self.root)
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if k in os.environ}  # no secrets
        proc = subprocess.run(argv, cwd=self.root, env=env, capture_output=True, text=True,
                              timeout=cap.timeout_s, shell=False)
        out = (proc.stdout + proc.stderr)[: cap.max_output]
        return f"exit code {proc.returncode}\n{out}"

    def _run_send_email(self, cap, a: EmailArgs) -> str:
        self.outbox.append(a.model_dump())
        return f"email queued to {a.to}"

    # ---------------------------------------------------------------- audit
    def _audit(self, tool: str, args: dict, result: ToolResult, seconds: float) -> None:
        if not self.audit_path:
            return
        entry = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "agent": self.policy.agent,
            "tool": tool,
            "args": redact({k: (v[:300] if isinstance(v, str) else v) for k, v in args.items()}),
            "decision": "allowed" if result.ok else ("denied" if result.denied else "error"),
            "reason": result.denied or result.error,
            "ms": round(seconds * 1000, 1),
            "output_chars": len(result.output),
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
