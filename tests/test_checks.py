import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from sandbox.checks import check_command, check_path, check_recipient, check_url
from sandbox.docker import docker_argv
from sandbox.policy import Policy, load_policy
from sandbox.redact import redact

POLICY = Path(__file__).resolve().parents[1] / "policies" / "research-agent.yaml"


def dns(mapping):
    def resolve(host):
        if host not in mapping:
            raise OSError("no such host")
        return mapping[host]
    return resolve


PUBLIC = dns({"api.github.com": ["140.82.112.6"], "en.wikipedia.org": ["185.15.59.224"],
              "evil.wikipedia.org": ["10.0.0.7"], "v6.wikipedia.org": ["::1"], "mixed.wikipedia.org": ["185.15.59.224", "192.168.1.5"]})
DOMAINS = ["api.github.com", "*.wikipedia.org"]


def test_policy_loads_and_resolves_root_from_file_location():
    p = load_policy(POLICY)
    assert p.agent == "research-agent"
    assert Path(p.root).is_absolute() and Path(p.root).name == "workspace"
    assert p.tools.send_email.require_approval is True


def test_policy_rejects_typos_and_bad_regex():
    base = {"agent": "a", "root": ".", "tools": {}}
    with pytest.raises(ValidationError):
        Policy.model_validate({**base, "tools": {"read_fle": {"paths": ["x"]}}})  # typo -> error, not ignored
    with pytest.raises(ValidationError):
        Policy.model_validate({**base, "tools": {"run_command": {"commands": {"python": "("}}}})
    with pytest.raises(ValidationError):
        Policy.model_validate({**base, "tools": {"run_command": {"commands": {"/bin/sh": ".*"}}}})


def test_paths(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("x")
    root = tmp_path.resolve()
    assert check_path(root, "docs/a.md", ["docs/**"])[1] is None
    assert "escapes" in check_path(root, "../outside", ["**"])[1]
    assert "escapes" in check_path(root, "docs/../../x", ["**"])[1]
    assert "not in the allowed" in check_path(root, "secret.txt", ["docs/**"])[1]
    assert check_path(root, "", ["**"])[1]


def test_symlink_escape(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (tmp_path / "root").mkdir()
    try:
        os.symlink(outside, tmp_path / "root" / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need extra privileges here")
    assert "escapes" in check_path((tmp_path / "root").resolve(), "link.txt", ["**"])[1]


@pytest.mark.parametrize("url, expected", [
    ("https://api.github.com/repos/x", None),
    ("https://en.wikipedia.org/wiki/X", None),
    ("https://wikipedia.org/", "not in the allowlist"),          # wildcard needs a subdomain
    ("https://evilwikipedia.org/", "not in the allowlist"),      # suffix trick
    ("https://api.github.com.evil.example/", "not in the allowlist"),
    ("ftp://api.github.com/", "scheme"),
    ("file:///etc/passwd", "scheme"),
    ("https://user:pass@api.github.com/", "credentials"),
    ("http://169.254.169.254/latest/", "raw IP"),
    ("http://[::1]:8080/", "raw IP"),
    ("https://evil.wikipedia.org/", "non-public"),
    ("https://v6.wikipedia.org/", "non-public"),
    ("https://mixed.wikipedia.org/", "non-public"),               # one private IP is enough to refuse
    ("https://unknown.wikipedia.org/", "DNS lookup failed"),
])
def test_urls_and_ssrf(url, expected):
    reason = check_url(url, DOMAINS, PUBLIC)
    assert reason is None if expected is None else expected in reason


@pytest.mark.parametrize("command, args, ok", [
    ("python", ["scripts/stats.py"], True),
    ("python", ["-c", "print(1)"], False),
    ("python", ["scripts/stats.py; rm -rf /"], False),
    ("python", ["scripts/$(whoami).py"], False),
    ("python", ["../scripts/stats.py"], False),
    ("bash", ["-c", "ls"], False),
])
def test_commands(command, args, ok):
    assert (check_command(command, args, {"python": r"^scripts/[a-z_]+\.py$"}) is None) is ok


def test_recipients():
    allowed = ["*@company.example", "ceo@partner.example"]
    assert check_recipient("Ann@Company.example", allowed) is None
    assert check_recipient("ceo@partner.example", allowed) is None
    assert check_recipient("x@company.example.evil.example", allowed)
    assert check_recipient("a@company.example,b@evil.example", allowed)
    assert check_recipient("not-an-email", allowed)


def test_redaction():
    text = "key gsk_abcdefghijklmnopqrstuvwx and Bearer abc.def.ghi123456 password=hunter2 AKIAABCDEFGHIJKLMNOP"
    out = redact({"x": text, "list": ["ghp_abcdefghijklmnopqrstuvwxyz12"]})
    assert "gsk_" not in out["x"] and "hunter2" not in out["x"] and "AKIA" not in out["x"]
    assert "abc.def.ghi" not in out["x"] and "ghp_" not in out["list"][0]


def test_docker_argv_is_hardened(tmp_path):
    argv = docker_argv("python", ["scripts/a.py"], tmp_path)
    joined = " ".join(argv)
    for flag in ["--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--pids-limit",
                 "--memory", "--user 65534:65534", ":/work:ro"]:
        assert flag in joined
    assert argv[-2:] == ["python", "scripts/a.py"]
