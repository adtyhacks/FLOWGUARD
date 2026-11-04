"""PNRI (Platform-Normalized Risk Index) Scoring Engine for FLOWGUARD."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

# Canonical severity weights
SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}

# Canonical scenario weights and expected severities
SCENARIO_WEIGHTS: dict[str, int] = {
    "TC-01": 25,  # CRITICAL: Payment Bypass
    "TC-02": 15,  # HIGH: Coupon Reuse
    "TC-03": 15,  # HIGH: Duplicate Order Creation
    "TC-04": 25,  # CRITICAL: Order IDOR
    "TC-05": 15,  # HIGH: Invalid Workflow Transitions
    "TC-06": 15,  # HIGH: Concurrent Checkout Race
    "TC-07": 15,  # HIGH: Client-Side Price Tampering
}

SCENARIO_SEVERITIES: dict[str, str] = {
    "TC-01": "CRITICAL",
    "TC-02": "HIGH",
    "TC-03": "HIGH",
    "TC-04": "CRITICAL",
    "TC-05": "HIGH",
    "TC-06": "HIGH",
    "TC-07": "HIGH",
}

MAX_RAW_SCORE: int = 125
TOTAL_SCENARIO_COUNT: int = 7


def get_risk_band(pnri_score: float) -> str:
    """Return the qualitative risk band for a normalized PNRI score (0.0 to 100.0).

    Interpretation:
      - 0.0  to 19.99: Low
      - 20.0 to 49.99: Moderate
      - 50.0 to 74.99: High
      - 75.0 to 100.0: Critical
    """
    if pnri_score < 20.0:
        return "Low"
    if pnri_score < 50.0:
        return "Moderate"
    if pnri_score < 75.0:
        return "High"
    return "Critical"


@dataclass(frozen=True)
class PNRIScoreResult:
    """Detailed result of a PNRI scoring evaluation."""

    raw_score: int
    max_raw_score: int
    pnri_score: float
    risk_band: str
    confirmed_scenario_ids: tuple[str, ...]
    completeness_pct: float
    total_scenarios: int
    conclusive_scenarios: int
    inconclusive_scenarios: int
    error_scenarios: int
    is_complete: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_score": self.raw_score,
            "max_raw_score": self.max_raw_score,
            "pnri_score": self.pnri_score,
            "risk_band": self.risk_band,
            "confirmed_scenario_ids": list(self.confirmed_scenario_ids),
            "completeness_pct": self.completeness_pct,
            "total_scenarios": self.total_scenarios,
            "conclusive_scenarios": self.conclusive_scenarios,
            "inconclusive_scenarios": self.inconclusive_scenarios,
            "error_scenarios": self.error_scenarios,
            "is_complete": self.is_complete,
        }


def calculate_pnri(
    confirmed_findings: Sequence[Any],
    scenario_results: Sequence[Any] | None = None,
    *,
    total_expected_scenarios: int = TOTAL_SCENARIO_COUNT,
) -> PNRIScoreResult:
    """Compute the deterministic PNRI score and assessment completeness.

    Args:
        confirmed_findings: Iterable of Finding objects or dicts representing confirmed vulnerabilities.
        scenario_results: Optional iterable of ScenarioResult objects for completeness calculation.
        total_expected_scenarios: Expected total count of scenarios in the suite (default 7).

    Returns:
        PNRIScoreResult containing raw score, normalized score (0–100), risk band, and completeness metrics.

    Raises:
        ValueError: If an unknown scenario ID or invalid severity is encountered.
    """
    if total_expected_scenarios <= 0:
        raise ValueError("total_expected_scenarios must be greater than zero.")

    # Deduplicate confirmed findings by scenario_id
    seen_scenarios: set[str] = set()
    raw_score = 0

    for finding in confirmed_findings:
        # Support either Finding object (attributes) or dict
        if isinstance(finding, dict):
            scen_id = finding.get("scenario_id")
            severity = finding.get("severity")
        else:
            scen_id = getattr(finding, "scenario_id", None)
            severity = getattr(finding, "severity", None)

        if not isinstance(scen_id, str) or not scen_id.strip():
            raise ValueError(f"Invalid or missing scenario_id in finding: {finding!r}")

        scen_id = scen_id.strip().upper()
        if scen_id not in SCENARIO_WEIGHTS:
            raise ValueError(
                f"Unknown scenario_id '{scen_id}'. Supported scenarios: {sorted(SCENARIO_WEIGHTS.keys())}"
            )

        if severity is not None:
            if not isinstance(severity, str) or severity.strip().upper() not in SEVERITY_WEIGHTS:
                raise ValueError(
                    f"Invalid severity '{severity}' for finding in scenario {scen_id}. "
                    f"Supported severities: {sorted(SEVERITY_WEIGHTS.keys())}"
                )

        # Prevent duplicate findings from inflating scores
        if scen_id in seen_scenarios:
            continue

        seen_scenarios.add(scen_id)
        raw_score += SCENARIO_WEIGHTS[scen_id]

    # Calculate normalized PNRI: (raw_score / 125) * 100, clamped to 0.0 - 100.0
    # Use exact integer multiplication before division to avoid floating-point drift
    normalized = min(100.0, max(0.0, (raw_score * 100.0) / MAX_RAW_SCORE))
    pnri_score = round(normalized, 2)
    risk_band = get_risk_band(pnri_score)

    # Completeness calculation from scenario_results
    conclusive_count = 0
    inconclusive_count = 0
    error_count = 0
    total_eval_scenarios = len(scenario_results) if scenario_results is not None else len(seen_scenarios)
    total_scenarios = max(total_expected_scenarios, total_eval_scenarios)

    if scenario_results is not None:
        for result in scenario_results:
            status = getattr(result, "status", None) if not isinstance(result, dict) else result.get("status")
            if status in ("PASS", "FAIL"):
                conclusive_count += 1
            elif status == "INCONCLUSIVE":
                inconclusive_count += 1
            elif status == "ERROR":
                error_count += 1
            else:
                # Any unknown status treated as unconcluded
                error_count += 1

        completeness_pct = round(min(100.0, max(0.0, (conclusive_count * 100.0) / total_scenarios)), 2)
    else:
        # If scenario results not passed, completeness is 100% only if all expected scenarios evaluated
        conclusive_count = len(seen_scenarios)
        completeness_pct = round(min(100.0, max(0.0, (conclusive_count * 100.0) / total_scenarios)), 2)

    is_complete = completeness_pct >= 100.0 and inconclusive_count == 0 and error_count == 0

    return PNRIScoreResult(
        raw_score=raw_score,
        max_raw_score=MAX_RAW_SCORE,
        pnri_score=pnri_score,
        risk_band=risk_band,
        confirmed_scenario_ids=tuple(sorted(seen_scenarios)),
        completeness_pct=completeness_pct,
        total_scenarios=total_scenarios,
        conclusive_scenarios=conclusive_count,
        inconclusive_scenarios=inconclusive_count,
        error_scenarios=error_count,
        is_complete=is_complete,
    )
