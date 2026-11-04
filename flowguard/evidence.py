"""Evidence sanitization and recording utilities for FLOWGUARD."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .redaction import REDACTED, is_sensitive_key, sanitize_value
from .schemas import EvidenceRecord


def _is_sensitive_key(key: Any) -> bool:
    """Return True when a key is likely to contain sensitive data."""
    return is_sensitive_key(key)


def sanitize_payload(value: Any) -> Any:
    """Recursively sanitize sensitive keys from nested dictionaries and lists."""
    return sanitize_value(value)


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, Any]:
    """Redact sensitive HTTP headers while preserving useful structure."""
    if not headers:
        return {}

    redacted: dict[str, Any] = {}
    for key, value in dict(headers).items():
        if _is_sensitive_key(key):
            redacted[str(key)] = REDACTED
        else:
            redacted[str(key)] = sanitize_value(value)
    return redacted


def capture_evidence(
    *,
    scenario_id: str,
    endpoint: str,
    request_method: str,
    request_payload: Any | None = None,
    request_headers: Mapping[str, Any] | None = None,
    response_payload: Any | None = None,
    response_status_code: int | None = None,
    observed_state: Any | None = None,
    error: str | None = None,
) -> EvidenceRecord:
    """Build a sanitized evidence record suitable for scenario logs and exports."""
    request_summary = {
        "method": request_method,
        "endpoint": sanitize_value(endpoint),
        "headers": redact_headers(request_headers),
        "payload": sanitize_payload(request_payload),
    }

    response_summary = {
        "status_code": response_status_code,
        "payload": sanitize_payload(response_payload),
        "error": sanitize_payload(error) if error is not None else None,
    }

    return EvidenceRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        scenario_id=scenario_id,
        endpoint=sanitize_value(endpoint),
        request_summary=request_summary,
        response_summary=response_summary,
        observed_state=sanitize_payload(observed_state),
    )
