"""Remove secrets before anything is written to the audit log."""

from __future__ import annotations

import re

PATTERNS = [
    (re.compile(r"\b(sk|gsk|pk|rk)[-_][A-Za-z0-9_-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/-]{10,}=*"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api_key|apikey)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def redact(value):
    if isinstance(value, str):
        for rx, repl in PATTERNS:
            value = rx.sub(repl, value)
        return value
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
