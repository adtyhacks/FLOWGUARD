"""Tests for the FLOWGUARD Streamlit Dashboard, History Storage, and Charts."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.charts import (
    create_pnri_gauge,
    create_scenario_status_chart,
    create_severity_breakdown_chart,
)
from dashboard.app import get_severity_badge, get_status_badge
from flowguard.history import AssessmentHistoryStore
from flowguard.schemas import AssessmentSummary, EvidenceRecord, Finding, ScenarioResult


# ==============================================================================
# 1. ASSESSMENT HISTORY STORE TESTS
# ==============================================================================

class TestAssessmentHistoryStore:
    """Validate assessment history persistence, isolation, and sanitization."""

    def test_save_list_and_load_assessment(self, tmp_path: Path) -> None:
        """Verify save, list, and load operations using a dedicated temporary store."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        assert store.list_assessments() == []

        valid_id = "fg-asm-a1b2c3d4e5f6"
        summary = AssessmentSummary(
            assessment_id=valid_id,
            target="http://127.0.0.1:5000",
            mode="secure",
            start_time="2026-11-03T00:00:00Z",
            scenario_results=[
                ScenarioResult("TC-01", "Payment Bypass", "PASS", "E", "Safe")
            ],
            findings=[],
            raw_risk_score=0,
            pnri_score=0.0,
        )
        summary.risk_band = "Low"
        summary.completeness_pct = 100.0

        saved_path = store.save_assessment(summary)
        assert saved_path.exists()
        assert valid_id in saved_path.name

        assessments = store.list_assessments()
        assert len(assessments) == 1
        assert assessments[0]["assessment_id"] == valid_id
        assert assessments[0]["mode"] == "secure"
        assert assessments[0]["pnri_score"] == 0.0
        assert assessments[0]["risk_band"] == "Low"

        loaded = store.load_assessment(valid_id)
        assert loaded is not None
        assert loaded["assessment_id"] == valid_id
        assert len(loaded["scenario_results"]) == 1

        assert store.load_assessment("fg-asm-999999999999") is None

    def test_saved_assessment_is_strictly_sanitized(self, tmp_path: Path) -> None:
        """Verify that persisted JSON files never contain sensitive tokens or passwords."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)

        secret_password = "super-secret-password-xyz"
        secret_token = "secret-token-abcdef-12345"
        valid_id = "fg-asm-f6e5d4c3b2a1"

        summary = AssessmentSummary(
            assessment_id=valid_id,
            target="http://127.0.0.1:5000",
            mode="vulnerable",
            scenario_results=[
                ScenarioResult(
                    "TC-01",
                    "Payment Bypass",
                    "FAIL",
                    "E",
                    "A",
                    evidence=[
                        EvidenceRecord(
                            "2026-11-03T00:00:00Z",
                            "TC-01",
                            "/orders/1/checkout",
                            {"password": secret_password},
                            {"token": secret_token},
                        )
                    ],
                )
            ],
            findings=[
                Finding(
                    "FG-TC01-001",
                    "TC-01",
                    "Payment Bypass",
                    "CRITICAL",
                    f"Sensitive auth parameter was password: {secret_password}",
                    "Impact",
                    "Remediation",
                )
            ],
            raw_risk_score=25,
            pnri_score=20.0,
        )

        saved_path = store.save_assessment(summary)
        with open(saved_path, "r", encoding="utf-8") as f:
            raw_content = f.read()

        assert secret_password not in raw_content
        assert secret_token not in raw_content
        assert "***REDACTED***" in raw_content

    def test_load_assessment_empty_id(self, tmp_path: Path) -> None:
        """Requirement 1: Empty assessment ID is rejected before searching files."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        assert store.load_assessment("") is None
        assert store.load_assessment("   ") is None
        assert store.load_assessment(None) is None

    def test_load_assessment_invalid_id(self, tmp_path: Path) -> None:
        """Requirement 2: Invalid format assessment IDs are rejected without file access."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        assert store.load_assessment("invalid-id") is None
        assert store.load_assessment("fg-asm-123") is None
        assert store.load_assessment("fg-asm-123456789012345") is None
        assert store.load_assessment("fg-asm-xyz!@#$$%^&") is None
        assert store.load_assessment("test-asm-001") is None

    def test_load_assessment_path_traversal(self, tmp_path: Path) -> None:
        """Requirement 3: Path traversal strings are rejected immediately by format validation."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        assert store.load_assessment("../../etc/passwd") is None
        assert store.load_assessment("..\\..\\windows\\win.ini") is None
        assert store.load_assessment("/etc/shadow") is None
        assert store.load_assessment("../fg-asm-a1b2c3d4e5f6") is None

    def test_load_assessment_short_substring_id(self, tmp_path: Path) -> None:
        """Requirement 4: Substrings or prefixes of valid IDs are rejected."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        valid_id = "fg-asm-a1b2c3d4e5f6"
        summary = AssessmentSummary(
            assessment_id=valid_id,
            target="http://127.0.0.1:5000",
            mode="secure",
            scenario_results=[],
            findings=[],
        )
        store.save_assessment(summary)

        # Substrings must return None
        assert store.load_assessment("fg-asm") is None
        assert store.load_assessment("a1b2c3d4e5f6") is None
        assert store.load_assessment("fg-asm-a1b2c3") is None

    def test_load_assessment_valid_id(self, tmp_path: Path) -> None:
        """Requirement 5: A valid assessment ID is loaded successfully."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        valid_id = "fg-asm-a1b2c3d4e5f6"
        summary = AssessmentSummary(
            assessment_id=valid_id,
            target="http://127.0.0.1:5000",
            mode="secure",
            scenario_results=[],
            findings=[],
        )
        store.save_assessment(summary)

        loaded = store.load_assessment(valid_id)
        assert loaded is not None
        assert loaded["assessment_id"] == valid_id

    def test_load_assessment_filename_content_mismatch(self, tmp_path: Path) -> None:
        """Requirement 6: If filename contains valid ID but JSON assessment_id does not match, return None."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        valid_id = "fg-asm-a1b2c3d4e5f6"
        different_id = "fg-asm-000000000000"

        # Create file with valid_id in filename, but different_id in JSON payload
        fake_file = tmp_path / f"2026-11-03_secure_{valid_id}.json"
        with open(fake_file, "w", encoding="utf-8") as f:
            json.dump({"assessment_id": different_id, "mode": "secure"}, f)

        # Loading valid_id must detect content mismatch and return None
        assert store.load_assessment(valid_id) is None


# ==============================================================================
# 2. PLOTLY CHARTS TESTS
# ==============================================================================

class TestDashboardCharts:
    """Validate Plotly chart rendering and boundary behaviors."""

    def test_pnri_gauge_rendering(self) -> None:
        """Verify radial gauge properties for various risk bands."""
        fig_low = create_pnri_gauge(12.5, "Low")
        assert fig_low.data[0].type == "indicator"
        assert fig_low.data[0].value == 12.5

        fig_crit = create_pnri_gauge(100.0, "Critical")
        assert fig_crit.data[0].value == 100.0

    def test_severity_breakdown_chart_with_findings(self) -> None:
        """Verify donut chart when findings are present."""
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ]
        fig = create_severity_breakdown_chart(findings)
        assert fig.data[0].type == "pie"
        assert "CRITICAL" in fig.data[0].labels

    def test_severity_breakdown_chart_empty_placeholder(self) -> None:
        """Verify clean placeholder pie chart when zero findings exist."""
        fig = create_severity_breakdown_chart([])
        assert fig.data[0].type == "pie"
        assert "No Confirmed Findings" in fig.data[0].labels

    def test_scenario_status_chart_rendering(self) -> None:
        """Verify stacked bar chart reflecting all 4 status states."""
        scenario_results = [
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "FAIL"},
            {"status": "INCONCLUSIVE"},
            {"status": "ERROR"},
        ]
        fig = create_scenario_status_chart(scenario_results)
        assert len(fig.data) == 4
        bar_names = {t.name for t in fig.data}
        assert "PASS (Secure)" in bar_names
        assert "FAIL (Vulnerable)" in bar_names
        assert "INCONCLUSIVE" in bar_names
        assert "ERROR" in bar_names


# ==============================================================================
# 3. BADGE HELPERS TESTS
# ==============================================================================

class TestBadgeHelpers:
    """Validate HTML badge formatting."""

    def test_status_badges(self) -> None:
        assert "#28a745" in get_status_badge("PASS")
        assert "#dc3545" in get_status_badge("FAIL")
        assert "#ffc107" in get_status_badge("ERROR")
        assert "#6c757d" in get_status_badge("INCONCLUSIVE")

    def test_severity_badges(self) -> None:
        assert "#dc3545" in get_severity_badge("CRITICAL")
        assert "#fd7e14" in get_severity_badge("HIGH")
        assert "#ffc107" in get_severity_badge("MEDIUM")
        assert "#17a2b8" in get_severity_badge("LOW")


# ==============================================================================
# 4. STREAMLIT APPTEST TESTS
# ==============================================================================

class TestStreamlitApp:
    """Headless Streamlit UI tests using Streamlit AppTest."""

    def test_initial_app_render_does_not_auto_execute(self) -> None:
        """On initial load, the app displays landing state and does NOT execute assessments."""
        at = AppTest.from_file("dashboard/app.py").run()
        assert not at.exception

        # Verify title & sidebar elements exist
        sidebar_text = "".join(str(s.value) for s in at.sidebar.title)
        assert "FLOWGUARD" in sidebar_text

        # Verify initial session state: no assessment is running or completed
        assert at.session_state["is_running"] is False
        assert at.session_state["current_summary"] is None

    def test_app_renders_completed_assessment_metrics(self) -> None:
        """Verify dashboard rendering with a simulated completed assessment in session_state."""
        sample_summary = {
            "assessment_id": "fg-test-asm-123",
            "target": "http://127.0.0.1:5000",
            "mode": "vulnerable",
            "start_time": "2026-11-03T02:00:00Z",
            "end_time": "2026-11-03T02:01:00Z",
            "raw_risk_score": 125,
            "pnri_score": 100.0,
            "risk_band": "Critical",
            "completeness_pct": 100.0,
            "is_complete": True,
            "scenario_results": [
                {
                    "scenario_id": f"TC-0{i}",
                    "scenario_name": f"Scenario {i}",
                    "status": "FAIL",
                    "duration_ms": 120,
                    "actual_behavior": f"Vulnerability {i} detected",
                    "expected_behavior": "Invariant enforced",
                    "evidence": [],
                }
                for i in range(1, 8)
            ],
            "findings": [
                {
                    "id": "FG-TC01-001",
                    "scenario_id": "TC-01",
                    "title": "Payment Bypass",
                    "severity": "CRITICAL",
                    "description": "Flaw details",
                    "impact": "Financial loss",
                    "remediation": "Validate payments",
                    "evidence_references": ["Step 1: /orders/1/confirm"],
                }
            ],
        }

        at = AppTest.from_file("dashboard/app.py")
        at.session_state["current_summary"] = sample_summary
        at.run()

        assert not at.exception
        # Confirm metrics rendered
        metrics = [m.value for m in at.metric]
        assert "100.0%" in metrics
        assert "Critical" in metrics
        assert "125 / 125" in metrics
        assert "1" in metrics or 1 in metrics  # Confirmed Flaws count

    def test_incomplete_assessment_warning_displayed(self) -> None:
        """When an assessment is incomplete, a prominent warning is rendered."""
        incomplete_summary = {
            "assessment_id": "fg-test-incomplete",
            "target": "http://127.0.0.1:5000",
            "mode": "secure",
            "start_time": "2026-11-03T02:00:00Z",
            "raw_risk_score": 0,
            "pnri_score": 0.0,
            "risk_band": "Low",
            "completeness_pct": 71.4,
            "is_complete": False,
            "scenario_results": [
                {"scenario_id": "TC-01", "status": "PASS", "duration_ms": 50, "actual_behavior": "Safe"},
                {"scenario_id": "TC-02", "status": "ERROR", "duration_ms": 50, "actual_behavior": "Error"},
            ],
            "findings": [],
        }

        at = AppTest.from_file("dashboard/app.py")
        at.session_state["current_summary"] = incomplete_summary
        at.run()

        assert not at.exception
        # Warning banner must exist
        warnings = [w.value for w in at.warning]
        assert any("INCOMPLETE ASSESSMENT WARNING" in w for w in warnings)

    def test_app_renders_pdf_download_button(self) -> None:
        """When an assessment summary is loaded, a PDF report download button is presented."""
        sample_summary = {
            "assessment_id": "fg-asm-a1b2c3d4e5f6",
            "target": "http://127.0.0.1:5000",
            "mode": "secure",
            "start_time": "2026-11-03T02:00:00Z",
            "raw_risk_score": 0,
            "pnri_score": 0.0,
            "risk_band": "Low",
            "completeness_pct": 100.0,
            "is_complete": True,
            "scenario_results": [],
            "findings": [],
        }

        at = AppTest.from_file("dashboard/app.py")
        at.session_state["current_summary"] = sample_summary
        at.run()

        assert not at.exception
        # Download button exists with expected label
        dl_buttons = at.download_button
        assert len(dl_buttons) >= 1
        labels = [b.label for b in dl_buttons]
        assert any("Download PDF Report" in l for l in labels)
