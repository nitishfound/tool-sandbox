import json
import shutil
from pathlib import Path

import httpx
import pytest

from sandbox import ToolBroker, load_policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy(tmp_path):
    shutil.copytree(ROOT / "examples" / "workspace", tmp_path / "ws")
    p = load_policy(ROOT / "policies" / "research-agent.yaml")
    p.root = str(tmp_path / "ws")
    return p


def resolver(host):
    return {"api.github.com": ["140.82.112.6"], "en.wikipedia.org": ["185.15.59.224"]}[host]


def web(request):
    if request.url.path == "/big":
        return httpx.Response(200, content=b"x" * 600_000)
    if request.url.path == "/hop":
        return httpx.Response(302, headers={"location": "https://api.github.com/ok"})
    if request.url.path == "/bad-hop":
        return httpx.Response(301, headers={"location": "http://127.0.0.1/admin"})
    if request.url.path == "/loop":
        return httpx.Response(302, headers={"location": "/loop"})
    return httpx.Response(200, text="hello")


def make(policy, tmp_path, **kw):
    return ToolBroker(policy, resolver=resolver, http_transport=httpx.MockTransport(web),
                      audit_path=tmp_path / "audit.jsonl", **kw)


def test_unknown_or_ungranted_tools_are_denied(policy, tmp_path):
    b = make(policy, tmp_path)
    assert "not granted" in b.call("delete_file", {"path": "x"}).denied
    policy.tools.http_get = None
    assert "not granted" in b.call("http_get", {"url": "https://api.github.com/"}).denied


def test_argument_schema_is_strict(policy, tmp_path):
    b = make(policy, tmp_path)
    assert "bad arguments" in b.call("read_file", {"file": "docs/readme.md"}).denied
    assert "bad arguments" in b.call("read_file", {"path": "docs/readme.md", "mode": "rw"}).denied
    assert "bad arguments" in b.call("run_command", {"command": "python", "args": "scripts/x.py"}).denied


def test_files_read_write(policy, tmp_path):
    b = make(policy, tmp_path)
    assert "Quarterly goal" in b.call("read_file", {"path": "docs/readme.md"}).output
    assert b.call("write_file", {"path": "out/new/report.md", "content": "hi"}).ok
    assert (Path(policy.root) / "out" / "new" / "report.md").read_text() == "hi"
    assert b.call("write_file", {"path": "docs/readme.md", "content": "x"}).denied
    assert "larger than" in b.call("write_file", {"path": "out/big.txt", "content": "x" * 200_000}).denied
    assert b.call("read_file", {"path": "out/missing.md"}).error.startswith("FileNotFoundError")


def test_http_redirects_are_rechecked_and_size_is_capped(policy, tmp_path):
    b = make(policy, tmp_path)
    assert b.call("http_get", {"url": "https://api.github.com/hop"}).output == "HTTP 200\nhello"
    assert "redirect blocked" in b.call("http_get", {"url": "https://api.github.com/bad-hop"}).denied
    assert "too many redirects" in b.call("http_get", {"url": "https://api.github.com/loop"}).error
    assert "larger than" in b.call("http_get", {"url": "https://api.github.com/big"}).error


def test_commands_run_without_secrets(policy, tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "super-secret")
    (Path(policy.root) / "scripts" / "env_dump.py").write_text("import os; print(sorted(os.environ))")
    b = make(policy, tmp_path)
    out = b.call("run_command", {"command": "python", "args": ["scripts/env_dump.py"]}).output
    assert out.startswith("exit code 0") and "GROQ_API_KEY" not in out
    stats = b.call("run_command", {"command": "python", "args": ["scripts/ticket_stats.py"]}).output
    assert "tickets=5 average_hours=6.0" in stats


def test_approval_required(policy, tmp_path):
    email = {"to": "a@company.example", "subject": "Weekly report", "body": "hi"}
    assert "no approver" in make(policy, tmp_path).call("send_email", email).denied
    assert "rejected" in make(policy, tmp_path, approver=lambda t, a: False).call("send_email", email).denied
    seen = []
    b = make(policy, tmp_path, approver=lambda t, a: seen.append(a) or True)
    assert b.call("send_email", email).ok and b.outbox[0]["to"] == "a@company.example"
    assert seen[0]["subject"] == "Weekly report"


def test_budgets(policy, tmp_path):
    b = make(policy, tmp_path)
    results = [b.call("http_get", {"url": "https://api.github.com/x"}) for _ in range(12)]
    assert sum(r.ok for r in results) == 10
    assert "budget for http_get exhausted" in results[-1].denied
    policy.budgets.max_calls = 10  # 10 calls were authorized so far
    assert "call budget exhausted" in b.call("read_file", {"path": "docs/readme.md"}).denied


def test_audit_log_records_every_call_with_secrets_redacted(policy, tmp_path):
    b = make(policy, tmp_path)
    b.call("write_file", {"path": "out/x.txt", "content": "token: ghp_abcdefghijklmnopqrstuvwxyz1234"})
    b.call("read_file", {"path": "../../etc/passwd"})
    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [entry["decision"] for entry in lines] == ["allowed", "denied"]
    assert "ghp_" not in json.dumps(lines[0]) and "escapes" in lines[1]["reason"]
    assert lines[0]["agent"] == "research-agent" and "ms" in lines[0]


def test_result_text_for_the_model(policy, tmp_path):
    r = make(policy, tmp_path).call("read_file", {"path": "../x"})
    assert r.for_model().startswith("DENIED by policy:")


def test_demo_runs(capsys):
    from sandbox.__main__ import main

    main()
    out = capsys.readouterr().out
    assert "7 allowed, 16 blocked" in out and "[REDACTED_API_KEY]" in out
