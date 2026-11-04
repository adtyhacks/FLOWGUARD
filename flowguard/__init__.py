"""FLOWGUARD foundation and assessment engine package.

This package contains the client, typed schemas, configuration, evidence collection,
canonical findings, PNRI scoring, and assessment orchestrator. It intentionally
does not import ShopZone business logic or SQLAlchemy models.
"""

from .auth import AuthSession, SyntheticUser, SyntheticUserManager
from .client import FlowGuardClient
from .config import FlowGuardConfig
from .evidence import capture_evidence, redact_headers, sanitize_payload
from .findings import CANONICAL_FINDINGS, build_finding_from_scenario_result, extract_findings_from_results
from .reporting import PDFReportGenerator, generate_pdf_report
from .runner import AssessmentRunner
from .schemas import ApiResult, AssessmentSummary, EvidenceRecord, Finding, ScenarioResult
from .scoring import calculate_pnri, get_risk_band, PNRIScoreResult

__all__ = [
    "FlowGuardClient",
    "FlowGuardConfig",
    "SyntheticUser",
    "AuthSession",
    "SyntheticUserManager",
    "ApiResult",
    "EvidenceRecord",
    "ScenarioResult",
    "Finding",
    "AssessmentSummary",
    "capture_evidence",
    "redact_headers",
    "sanitize_payload",
    "CANONICAL_FINDINGS",
    "build_finding_from_scenario_result",
    "extract_findings_from_results",
    "AssessmentRunner",
    "calculate_pnri",
    "get_risk_band",
    "PNRIScoreResult",
    "PDFReportGenerator",
    "generate_pdf_report",
]
