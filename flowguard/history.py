"""Local assessment history persistence for FLOWGUARD.

Stores sanitized AssessmentSummary JSON files in a dedicated storage directory
completely separate from ShopZone databases.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .redaction import sanitize_value
from .schemas import AssessmentSummary


DEFAULT_HISTORY_DIR = Path(__file__).resolve().parent.parent / "instance" / "flowguard_history"
ASSESSMENT_ID_PATTERN = re.compile(r"^fg-asm-[a-f0-9]{12}$", re.IGNORECASE)


def validate_assessment_id(assessment_id: Any) -> str | None:
    """Validate assessment ID format.

    Requires a non-empty string adhering to ^fg-asm-[a-f0-9]{12}$.
    Returns normalized lowercase ID or None if invalid.
    """
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        return None
    normalized = assessment_id.strip().lower()
    if not ASSESSMENT_ID_PATTERN.fullmatch(normalized):
        return None
    return normalized


class AssessmentHistoryStore:
    """Thread-safe, file-based store for sanitized FLOWGUARD assessments."""

    def __init__(self, storage_dir: Path | str | None = None) -> None:
        self.storage_dir = Path(storage_dir or DEFAULT_HISTORY_DIR)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save_assessment(self, summary: AssessmentSummary) -> Path:
        """Persist a sanitized AssessmentSummary to a JSON file."""
        data = sanitize_value(summary.to_dict())
        # Add extended metadata if present on summary object
        data["risk_band"] = getattr(summary, "risk_band", "N/A")
        data["completeness_pct"] = getattr(summary, "completeness_pct", 100.0)
        data["is_complete"] = getattr(summary, "is_complete", True)
        data["conclusive_count"] = getattr(summary, "conclusive_count", len(summary.scenario_results))
        data["inconclusive_count"] = getattr(summary, "inconclusive_count", 0)
        data["error_count"] = getattr(summary, "error_count", 0)

        data = sanitize_value(data)

        safe_ts = summary.start_time.replace(":", "-").replace(".", "-")
        filename = f"{safe_ts}_{summary.mode}_{summary.assessment_id}.json"
        target_path = self.storage_dir / filename

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return target_path

    def list_assessments(self) -> list[dict[str, Any]]:
        """List all historical assessments ordered from newest to oldest."""
        assessments: list[dict[str, Any]] = []
        if not self.storage_dir.exists():
            return assessments

        for file_path in sorted(self.storage_dir.glob("*.json"), reverse=True):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    assessments.append({
                        "file_path": str(file_path),
                        "assessment_id": data.get("assessment_id", file_path.stem),
                        "mode": data.get("mode", "unknown"),
                        "start_time": data.get("start_time", ""),
                        "end_time": data.get("end_time", ""),
                        "raw_risk_score": data.get("raw_risk_score", 0),
                        "pnri_score": data.get("pnri_score", 0.0),
                        "risk_band": data.get("risk_band", "N/A"),
                        "findings_count": len(data.get("findings", [])),
                        "scenarios_count": len(data.get("scenario_results", [])),
                        "completeness_pct": data.get("completeness_pct", 100.0),
                    })
            except Exception:
                continue

        return assessments

    def load_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        """Load an assessment by ID with strict validation."""
        valid_id = validate_assessment_id(assessment_id)
        if valid_id is None:
            return None

        for file_path in self.storage_dir.glob("*.json"):
            if valid_id in file_path.name.lower():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict) and data.get("assessment_id") == valid_id:
                            return data
                except Exception:
                    continue
        return None
