"""Pure check functions. Each returns None if OK, or a human-readable reason to deny."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

Resolver = Callable[[str], list[str]]


def resolve_host(host: str) -> list[str]:
    """All IP addresses a hostname resolves to."""
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})


# ---------------------------------------------------------------- file paths
def check_path(root: Path, rel: str, patterns: list[str]) -> tuple[Path | None, str | None]:
    """Resolve `rel` inside `root` (following '..' and symlinks) and match it against allowed globs."""
    if not rel or "\x00" in rel:
        return None, "empty or invalid path"
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        return None, f"path escapes the sandbox root: {rel!r}"
    relative = target.relative_to(root).as_posix()
    if not any(fnmatch.fnmatchcase(relative, pat) or relative == pat.rstrip("/*") for pat in patterns):
        return None, f"path {relative!r} is not in the allowed paths {patterns}"
    return target, None


# --------------------------------------------------------------- URLs / SSRF
def _host_allowed(host: str, domains: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for d in domains:
        d = d.lower()
        if d.startswith("*."):
            if host.endswith(d[1:]) and host != d[2:]:
                return True
        elif host == d:
            return True
    return False


def check_url(url: str, domains: list[str], resolver: Resolver = resolve_host) -> str | None:
    """Allow only http(s) to allowlisted domains that resolve to PUBLIC IPs.

    SSRF (server-side request forgery): an agent tricked into fetching
    http://169.254.169.254/ (cloud credentials), http://localhost:8080/admin or
    an internal IP can reach things the attacker can't. So we check the
    scheme, the host allowlist, and every IP the host resolves to."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "malformed URL"
    if parts.scheme not in ("http", "https"):
        return f"scheme {parts.scheme!r} is not allowed"
    if parts.username or parts.password:
        return "credentials in URLs are not allowed"
    host = parts.hostname
    if not host:
        return "URL has no host"
    try:
        ipaddress.ip_address(host)
        return "raw IP addresses are not allowed; use an allowlisted domain"
    except ValueError:
        pass
    if not _host_allowed(host, domains):
        return f"domain {host!r} is not in the allowlist"
    try:
        ips = resolver(host)
    except OSError as exc:
        return f"DNS lookup failed for {host!r}: {exc}"
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or addr.is_multicast:
            return f"{host!r} resolves to non-public address {ip} (possible SSRF / DNS rebinding)"
    return None


# ------------------------------------------------------------------ commands
SHELL_META = re.compile(r"[;&|`$<>(){}\[\]*?!~\n\r\\]")


def check_command(command: str, args: list[str], allowed: dict[str, str]) -> str | None:
    """Only allowlisted programs; every argument must match that program's regex.
    Arguments are passed as a list (no shell), and shell metacharacters are rejected anyway."""
    if command not in allowed:
        return f"command {command!r} is not allowed (allowed: {sorted(allowed)})"
    rx = re.compile(allowed[command])
    for a in args:
        if SHELL_META.search(a):
            return f"argument {a!r} contains shell metacharacters"
        if not rx.fullmatch(a):
            return f"argument {a!r} does not match the allowed pattern for {command!r}"
    return None


# --------------------------------------------------------------------- email
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def check_recipient(address: str, allowed: list[str]) -> str | None:
    address = address.strip().lower()
    if not EMAIL_RE.fullmatch(address):
        return f"invalid email address {address!r}"
    for pattern in allowed:
        pattern = pattern.lower()
        if pattern.startswith("*@") and address.endswith(pattern[1:]):
            return None
        if address == pattern:
            return None
    return f"recipient {address!r} is not allowed"
