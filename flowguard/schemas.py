"""Typed schemas for FLOWGUARD API responses, evidence, findings, and summary results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .redaction import sanitize_value


class ApiResult:
    """Container for a single HTTP response result."""

    def __init__(
        self,
        status_code: int,
        ok: bool,
        payload: Any | None,
        elapsed_ms: float,
        request_method: str,
        endpoint: str,
        error: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.ok = ok
        self.payload = payload
        self.elapsed_ms = elapsed_ms
        self.request_method = request_method
        self.endpoint = endpoint
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        """Return a safe JSON-friendly representation."""
        return sanitize_value({
            "status_code": self.status_code,
            "ok": self.ok,
            "payload": self.payload,
            "elapsed_ms": self.elapsed_ms,
            "request_method": self.request_method,
            "endpoint": self.endpoint,
            "error": self.error,
        })

    def __repr__(self) -> str:
        """Keep secrets out of accidental debug logging."""
        return (
            "ApiResult("
            f"status_code={self.status_code!r}, ok={self.ok!r}, "
            f"payload={sanitize_value(self.payload)!r}, elapsed_ms={self.elapsed_ms!r}, "
            f"request_method={self.request_method!r}, endpoint={sanitize_value(self.endpoint)!r}, "
            f"error={sanitize_value(self.error)!r})"
        )


class EvidenceRecord:
    """Sanitized evidence captured during an assessment step."""

    def __init__(
        self,
        timestamp: str,
        scenario_id: str,
        endpoint: str,
        request_summary: dict[str, Any],
        response_summary: dict[str, Any],
        observed_state: dict[str, Any] | None = None,
    ) -> None:
        self.timestamp = timestamp
        self.scenario_id = scenario_id
        self.endpoint = endpoint
        self.request_summary = request_summary
        self.response_summary = response_summary
        self.observed_state = observed_state

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return sanitize_value({
            "timestamp": self.timestamp,
            "scenario_id": self.scenario_id,
            "endpoint": self.endpoint,
            "request_summary": self.request_summary,
            "response_summary": self.response_summary,
            "observed_state": self.observed_state,
        })

    def __repr__(self) -> str:
        """Keep direct or subsequently modified evidence safe to inspect."""
        return f"EvidenceRecord({self.to_dict()!r})"


class ScenarioResult:
    """Outcome of a single security scenario assessment."""

    VALID_STATUSES = {"PASS", "FAIL", "ERROR", "INCONCLUSIVE"}

    def __init__(
        self,
        scenario_id: str,
        scenario_name: str,
        status: str,
        expected_behavior: str,
        actual_behavior: str,
        evidence: list[EvidenceRecord] | None = None,
        error: str | None = None,
        duration_ms: int = 0,
    ) -> None:
        if status not in self.VALID_STATUSES:
            raise ValueError("ScenarioResult.status must be one of: PASS, FAIL, ERROR, INCONCLUSIVE.")
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.status = status
        self.expected_behavior = expected_behavior
        self.actual_behavior = actual_behavior
        self.evidence = list(evidence or [])
        self.error = error
        self.duration_ms = duration_ms

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, sanitize_value(value))

    def to_dict(self) -> dict[str, Any]:
        """Return a sanitized scenario export, including free-form diagnostics."""
        return sanitize_value({
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "status": self.status,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "evidence": [record.to_dict() for record in self.evidence],
            "error": self.error,
            "duration_ms": self.duration_ms,
        })

    def __repr__(self) -> str:
        return f"ScenarioResult({self.to_dict()!r})"


class Finding:
    """Security finding raised by a scenario or aggregate assessment."""

    def __init__(
        self,
        id: str,
        scenario_id: str,
        title: str,
        severity: str,
        description: str,
        impact: str,
        remediation: str,
        evidence_references: list[str] | None = None,
    ) -> None:
        self.id = id
        self.scenario_id = scenario_id
        self.title = title
        self.severity = severity
        self.description = description
        self.impact = impact
        self.remediation = remediation
        self.evidence_references = list(evidence_references or [])

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, sanitize_value(value))

    def to_dict(self) -> dict[str, Any]:
        return sanitize_value({
            "id": self.id,
            "scenario_id": self.scenario_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence_references": self.evidence_references,
        })

    def __repr__(self) -> str:
        return f"Finding({self.to_dict()!r})"


@dataclass
class AssessmentSummary:
    """Top-level summary of a completed FLOWGUARD assessment."""

    assessment_id: str
    target: str
    mode: str
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str | None = None
    scenario_results: list[ScenarioResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw_risk_score: int = 0
    pnri_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation for export."""
        data: dict[str, Any] = {
            "assessment_id": self.assessment_id,
            "target": self.target,
            "mode": self.mode,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "scenario_results": [r.to_dict() for r in self.scenario_results],
            "findings": [f.to_dict() for f in self.findings],
            "raw_risk_score": self.raw_risk_score,
            "pnri_score": self.pnri_score,
        }
        for attr in ("risk_band", "completeness_pct", "is_complete", "conclusive_count", "inconclusive_count", "error_count"):
            if hasattr(self, attr) and getattr(self, attr) is not None:
                data[attr] = getattr(self, attr)
        return sanitize_value(data)

    def __repr__(self) -> str:
        return f"AssessmentSummary({self.to_dict()!r})"
