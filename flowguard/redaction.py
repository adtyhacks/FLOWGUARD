"""Redaction helpers for FLOWGUARD diagnostics and evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "***REDACTED***"

_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "bearer",
    "admin_key",
    "x_admin_key",
    "api_key",
    "apikey",
    "session",
    "cookie",
    "set_cookie",
    "jwt",
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>\b(?:password|passwd|secret|access[_ -]?token|refresh[_ -]?token|token|authorization|bearer|admin[_ -]?key|x[_ -]?admin[_ -]?key|api[_ -]?key|apikey|session(?:[_ -]?token)?|cookie|set[_ -]?cookie|jwt)\b)(?P<separator>\s*[:=]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_SENSITIVE_NATURAL_LANGUAGE = re.compile(
    r"(?i)(?P<key>\b(?:password|passwd|secret|access[_ -]?token|refresh[_ -]?token|token|authorization|admin[_ -]?key|x[_ -]?admin[_ -]?key|api[_ -]?key|apikey|session(?:[_ -]?token)?|cookie|jwt)\b)(?P<separator>\s+(?:is|was|contains)\s+)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&.]+)"
)
_BEARER_VALUE = re.compile(
    r"(?i)\bBearer\s+(?:token\s+)?(?!(?:\"token\"|'token'|token)(?:$|[.,;]))(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_URL_USERINFO = re.compile(
    r"(?i)(?P<scheme>https?://)(?P<userinfo>[^\s/?#@]*@)(?P<host>[^\s/?#]+)"
)
_SENSITIVE_QUERY_VALUE = re.compile(
    r"(?i)(?P<prefix>[?&#;](?:password|passwd|secret|access[_-]?token|refresh[_-]?token|token|authorization|admin[_-]?key|x[_-]?admin[_-]?key|api[_-]?key|apikey|session(?:[_-]?token)?|cookie|jwt)=)(?P<value>[^&#;\s]*)"
)


def is_sensitive_key(key: Any) -> bool:
    normalized = str(key).lower().replace("-", "_").replace(" ", "_")
    return any(token in normalized for token in _SENSITIVE_KEY_TOKENS)


def redact_text(value: str) -> str:
    """Redact secret values embedded in server messages, URLs, or exceptions."""
    text = _URL_USERINFO.sub(lambda match: f"{match.group('scheme')}{REDACTED}@{match.group('host')}", value)
    text = _SENSITIVE_QUERY_VALUE.sub(lambda match: f"{match.group('prefix')}{REDACTED}", text)
    text = _BEARER_VALUE.sub(lambda match: f"Bearer {REDACTED}", text)
    text = _SENSITIVE_ASSIGNMENT.sub(
        lambda match: f"{match.group('key')}{match.group('separator')}{REDACTED}",
        text,
    )
    return _SENSITIVE_NATURAL_LANGUAGE.sub(
        lambda match: f"{match.group('key')}{match.group('separator')}{REDACTED}",
        text,
    )


def sanitize_value(value: Any) -> Any:
    """Recursively redact sensitive mapping values and secrets in text."""
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            sanitized[str(key)] = REDACTED if is_sensitive_key(key) else sanitize_value(item)
        return sanitized

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize_value(item) for item in value]

    if isinstance(value, (bytes, bytearray)):
        return redact_text(bytes(value).decode("utf-8", errors="replace"))

    if isinstance(value, str):
        return redact_text(value)

    return value