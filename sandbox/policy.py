"""Policy = the exact capabilities one agent is granted. Anything not listed is denied.

Example (policies/research-agent.yaml):

    agent: research-agent
    root: examples/workspace
    tools:
      read_file:   {paths: ["docs/**", "out/**"]}
      write_file:  {paths: ["out/**"], max_bytes: 100000}
      http_get:    {domains: ["api.github.com", "*.wikipedia.org"], max_bytes: 500000}
      run_command: {commands: {python: '^scripts/[a-z_]+\\.py$'}, timeout_s: 10}
      send_email:  {recipients: ["*@company.example"], require_approval: true}
    budgets: {max_calls: 30, per_tool: {http_get: 10}}
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a typo in a policy must be an error, not silently ignored


class FileCap(_Strict):
    paths: list[str] = Field(min_length=1, description="glob patterns relative to root, e.g. 'docs/**'")
    max_bytes: int = 200_000
    require_approval: bool = False


class HttpCap(_Strict):
    domains: list[str] = Field(min_length=1, description="exact hosts or '*.example.com' wildcards")
    max_bytes: int = 500_000
    timeout_s: float = 10
    max_redirects: int = 3
    require_approval: bool = False


class CommandCap(_Strict):
    commands: dict[str, str] = Field(description="program -> regex every argument must match")
    timeout_s: float = 10
    max_output: int = 20_000
    require_approval: bool = False

    @field_validator("commands")
    @classmethod
    def valid_regex(cls, v: dict[str, str]) -> dict[str, str]:
        for prog, rx in v.items():
            try:
                re.compile(rx)
            except re.error as exc:  # pydantic only turns ValueError into a validation error
                raise ValueError(f"invalid regex for {prog!r}: {exc}") from exc
            if "/" in prog or "\\" in prog:
                raise ValueError(f"command {prog!r} must be a bare program name")
        return v


class EmailCap(_Strict):
    recipients: list[str] = Field(min_length=1, description="exact addresses or '*@domain' wildcards")
    max_body: int = 5_000
    require_approval: bool = True


class Tools(_Strict):
    read_file: FileCap | None = None
    write_file: FileCap | None = None
    list_dir: FileCap | None = None
    http_get: HttpCap | None = None
    run_command: CommandCap | None = None
    send_email: EmailCap | None = None


class Budgets(_Strict):
    max_calls: int = 50
    per_tool: dict[str, int] = Field(default_factory=dict)


class Policy(_Strict):
    agent: str
    root: str
    tools: Tools
    budgets: Budgets = Budgets()

    def root_path(self, base: Path | None = None) -> Path:
        p = Path(self.root)
        return (p if p.is_absolute() else (base or Path.cwd()) / p).resolve()


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy. A relative `root` is resolved from the policy file's folder."""
    path = Path(path)
    policy = Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    policy.root = str(policy.root_path(path.parent.resolve()))
    return policy
