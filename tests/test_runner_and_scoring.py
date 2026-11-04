"""Tests for FLOWGUARD Assessment Engine, PNRI Scoring, Findings, Runner, and CLI."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from unittest.mock import MagicMock, patch

import pytest

from flowguard.client import FlowGuardClient
from flowguard.config import FlowGuardConfig
from flowguard.findings import (
    CANONICAL_FINDINGS,
    build_finding_from_scenario_result,
    extract_findings_from_results,
)
from flowguard.runner import AssessmentRunner
from flowguard.schemas import AssessmentSummary, EvidenceRecord, Finding, ScenarioResult
from flowguard.scoring import (
    MAX_RAW_SCORE,
    SCENARIO_SEVERITIES,
    SCENARIO_WEIGHTS,
    SEVERITY_WEIGHTS,
    TOTAL_SCENARIO_COUNT,
    calculate_pnri,
    get_risk_band,
)
import run_assessment
from shopzone.config import TestingConfig


# ==============================================================================
# 1. PNRI SCORING ENGINE TESTS
# ==============================================================================

class TestPNRIScoringEngine:
    """Validate deterministic PNRI score calculations, normalization, and bounds."""

    def test_canonical_constants_integrity(self) -> None:
        """Verify weights sum up exactly to MAX_RAW_SCORE (125)."""
        assert MAX_RAW_SCORE == 125
        assert TOTAL_SCENARIO_COUNT == 7
        assert sum(SCENARIO_WEIGHTS.values()) == 125
        assert set(SCENARIO_WEIGHTS.keys()) == {
            "TC-01", "TC-02", "TC-03", "TC-04", "TC-05", "TC-06", "TC-07"
        }
        assert SCENARIO_WEIGHTS["TC-01"] == 25
        assert SCENARIO_WEIGHTS["TC-02"] == 15
        assert SCENARIO_WEIGHTS["TC-03"] == 15
        assert SCENARIO_WEIGHTS["TC-04"] == 25
        assert SCENARIO_WEIGHTS["TC-05"] == 15
        assert SCENARIO_WEIGHTS["TC-06"] == 15
        assert SCENARIO_WEIGHTS["TC-07"] == 15

    def test_risk_band_boundaries(self) -> None:
        """Verify qualitative risk band thresholds."""
        assert get_risk_band(0.0) == "Low"
        assert get_risk_band(12.0) == "Low"
        assert get_risk_band(19.9) == "Low"
        assert get_risk_band(20.0) == "Moderate"
        assert get_risk_band(35.5) == "Moderate"
        assert get_risk_band(49.9) == "Moderate"
        assert get_risk_band(50.0) == "High"
        assert get_risk_band(64.0) == "High"
        assert get_risk_band(74.9) == "High"
        assert get_risk_band(75.0) == "Critical"
        assert get_risk_band(80.0) == "Critical"
        assert get_risk_band(100.0) == "Critical"

    def test_all_seven_scenarios_passing_zero_risk(self) -> None:
        """Secure target where all scenarios pass produces 0.0 PNRI and Low risk."""
        scenario_results = [
            ScenarioResult(scen_id, f"Scenario {scen_id}", "PASS", "Expected", "Actual")
            for scen_id in SCENARIO_WEIGHTS
        ]
        result = calculate_pnri(confirmed_findings=[], scenario_results=scenario_results)

        assert result.raw_score == 0
        assert result.pnri_score == 0.0
        assert result.risk_band == "Low"
        assert result.completeness_pct == 100.0
        assert result.is_complete is True
        assert len(result.confirmed_scenario_ids) == 0

    def test_all_seven_vulnerable_findings_maximum_risk(self) -> None:
        """Vulnerable target where all 7 findings are confirmed produces 100.0 PNRI and Critical risk."""
        findings = [
            CANONICAL_FINDINGS[scen_id].create_finding()
            for scen_id in SCENARIO_WEIGHTS
        ]
        scenario_results = [
            ScenarioResult(scen_id, f"Scenario {scen_id}", "FAIL", "Expected", "Actual")
            for scen_id in SCENARIO_WEIGHTS
        ]
        result = calculate_pnri(confirmed_findings=findings, scenario_results=scenario_results)

        assert result.raw_score == 125
        assert result.max_raw_score == 125
        assert result.pnri_score == 100.0
        assert result.risk_band == "Critical"
        assert result.completeness_pct == 100.0
        assert result.is_complete is True
        assert len(result.confirmed_scenario_ids) == 7

    def test_mixed_findings_deterministic_calculations(self) -> None:
        """Verify exact mathematical normalization for various combinations."""
        # 1. TC-01 only: 25 / 125 * 100 = 20.0 (Moderate)
        f1 = [CANONICAL_FINDINGS["TC-01"].create_finding()]
        r1 = calculate_pnri(f1)
        assert r1.raw_score == 25
        assert r1.pnri_score == 20.0
        assert r1.risk_band == "Moderate"

        # 2. TC-02 only: 15 / 125 * 100 = 12.0 (Low)
        f2 = [CANONICAL_FINDINGS["TC-02"].create_finding()]
        r2 = calculate_pnri(f2)
        assert r2.raw_score == 15
        assert r2.pnri_score == 12.0
        assert r2.risk_band == "Low"

        # 3. TC-01 + TC-04 (both Critical): 50 / 125 * 100 = 40.0 (Moderate)
        f3 = [CANONICAL_FINDINGS["TC-01"].create_finding(), CANONICAL_FINDINGS["TC-04"].create_finding()]
        r3 = calculate_pnri(f3)
        assert r3.raw_score == 50
        assert r3.pnri_score == 40.0
        assert r3.risk_band == "Moderate"

        # 4. TC-01 + TC-04 + TC-02 + TC-03: (25 + 25 + 15 + 15) = 80 / 125 * 100 = 64.0 (High)
        f4 = [
            CANONICAL_FINDINGS["TC-01"].create_finding(),
            CANONICAL_FINDINGS["TC-04"].create_finding(),
            CANONICAL_FINDINGS["TC-02"].create_finding(),
            CANONICAL_FINDINGS["TC-03"].create_finding(),
        ]
        r4 = calculate_pnri(f4)
        assert r4.raw_score == 80
        assert r4.pnri_score == 64.0
        assert r4.risk_band == "High"

    def test_duplicate_findings_do_not_inflate_score(self) -> None:
        """Multiple finding objects for the same scenario must be deduplicated."""
        findings = [
            CANONICAL_FINDINGS["TC-01"].create_finding(),
            CANONICAL_FINDINGS["TC-01"].create_finding(),
            CANONICAL_FINDINGS["TC-01"].create_finding(),
        ]
        result = calculate_pnri(findings)
        assert result.raw_score == 25
        assert result.pnri_score == 20.0
        assert result.confirmed_scenario_ids == ("TC-01",)

    def test_inconclusive_and_error_contribute_zero_points_and_reduce_completeness(self) -> None:
        """INCONCLUSIVE and ERROR must contribute 0 risk points, but penalize completeness."""
        # 5 PASS, 1 INCONCLUSIVE, 1 ERROR -> 5 conclusive out of 7 = 71.43% completeness
        scenario_results = [
            ScenarioResult("TC-01", "Scenario TC-01", "PASS", "E", "A"),
            ScenarioResult("TC-02", "Scenario TC-02", "PASS", "E", "A"),
            ScenarioResult("TC-03", "Scenario TC-03", "PASS", "E", "A"),
            ScenarioResult("TC-04", "Scenario TC-04", "PASS", "E", "A"),
            ScenarioResult("TC-05", "Scenario TC-05", "PASS", "E", "A"),
            ScenarioResult("TC-06", "Scenario TC-06", "INCONCLUSIVE", "E", "A"),
            ScenarioResult("TC-07", "Scenario TC-07", "ERROR", "E", "A"),
        ]
        result = calculate_pnri(confirmed_findings=[], scenario_results=scenario_results)
        assert result.raw_score == 0
        assert result.pnri_score == 0.0
        assert result.completeness_pct == 71.43
        assert result.is_complete is False
        assert result.inconclusive_scenarios == 1
        assert result.error_scenarios == 1
        assert result.conclusive_scenarios == 5

    def test_invalid_scenario_id_raises_value_error(self) -> None:
        """Unknown scenario IDs raise ValueError."""
        invalid_finding = {"scenario_id": "TC-99", "severity": "HIGH"}
        with pytest.raises(ValueError, match="Unknown scenario_id 'TC-99'"):
            calculate_pnri([invalid_finding])

    def test_invalid_severity_raises_value_error(self) -> None:
        """Invalid severity string raises ValueError."""
        invalid_finding = {"scenario_id": "TC-01", "severity": "URGENT"}
        with pytest.raises(ValueError, match="Invalid severity 'URGENT'"):
            calculate_pnri([invalid_finding])

    def test_clamping_and_serialization(self) -> None:
        """Result dict is serializable and fields match."""
        res = calculate_pnri([])
        data = res.to_dict()
        assert data["raw_score"] == 0
        assert data["pnri_score"] == 0.0
        assert data["risk_band"] == "Low"
        assert isinstance(data["confirmed_scenario_ids"], list)


# ==============================================================================
# 2. FINDING ENGINE TESTS
# ==============================================================================

class TestFindingEngine:
    """Validate canonical security finding templates and extraction."""

    def test_all_seven_canonical_findings_registered(self) -> None:
        """Verify all 7 scenarios have complete canonical definitions."""
        assert len(CANONICAL_FINDINGS) == 7
        for scen_id in ("TC-01", "TC-02", "TC-03", "TC-04", "TC-05", "TC-06", "TC-07"):
            defn = CANONICAL_FINDINGS[scen_id]
            assert defn.scenario_id == scen_id
            assert defn.finding_id.startswith("FG-")
            assert defn.title
            assert defn.severity in ("CRITICAL", "HIGH")
            assert defn.cwe_id.startswith("CWE-")
            assert defn.description
            assert defn.impact
            assert defn.remediation

    def test_build_finding_from_failed_result(self) -> None:
        """A ScenarioResult with status FAIL correctly generates a Finding."""
        res = ScenarioResult(
            scenario_id="TC-01",
            scenario_name="Payment Bypass",
            status="FAIL",
            expected_behavior="Order remains unpaid.",
            actual_behavior="Order confirmed without payment.",
            evidence=[
                EvidenceRecord("2026-11-03T00:00:00Z", "TC-01", "/orders/1/confirm", {}, {})
            ],
        )
        finding = build_finding_from_scenario_result(res)
        assert finding is not None
        assert finding.scenario_id == "TC-01"
        assert finding.id == "FG-TC01-001"
        assert finding.severity == "CRITICAL"
        assert "CWE-840" in finding.description
        assert len(finding.evidence_references) == 1
        assert "Step 1: /orders/1/confirm" in finding.evidence_references[0]

    def test_build_finding_returns_none_for_pass_or_inconclusive(self) -> None:
        """Non-failing scenarios do not generate vulnerability findings."""
        pass_res = ScenarioResult("TC-01", "TC-01", "PASS", "E", "A")
        incon_res = ScenarioResult("TC-01", "TC-01", "INCONCLUSIVE", "E", "A")
        err_res = ScenarioResult("TC-01", "TC-01", "ERROR", "E", "A")

        assert build_finding_from_scenario_result(pass_res) is None
        assert build_finding_from_scenario_result(incon_res) is None
        assert build_finding_from_scenario_result(err_res) is None

    def test_extract_findings_from_results(self) -> None:
        """Extract only the confirmed findings from a mixed result list."""
        results = [
            ScenarioResult("TC-01", "TC-01", "FAIL", "E", "A"),
            ScenarioResult("TC-02", "TC-02", "PASS", "E", "A"),
            ScenarioResult("TC-03", "TC-03", "FAIL", "E", "A"),
            ScenarioResult("TC-04", "TC-04", "PASS", "E", "A"),
        ]
        findings = extract_findings_from_results(results)
        assert len(findings) == 2
        assert {f.scenario_id for f in findings} == {"TC-01", "TC-03"}


# ==============================================================================
# 3. ASSESSMENT ORCHESTRATOR TESTS
# ==============================================================================

class TestAssessmentRunner:
    """Validate AssessmentRunner execution, error containment, and summary generation."""

    def test_runner_initialization_validation(self) -> None:
        """Verify constructor parameter constraints."""
        cfg = FlowGuardConfig(base_url="http://127.0.0.1:5000", target_mode="secure")
        runner = AssessmentRunner(cfg, timeout=3.0, coupon_code="CYBERSEC20", num_workers_tc06=4)
        assert runner.timeout == 3.0
        assert runner.coupon_code == "CYBERSEC20"
        assert runner.num_workers_tc06 == 4

        with pytest.raises(ValueError, match="timeout must be greater than zero"):
            AssessmentRunner(timeout=0)

        with pytest.raises(ValueError, match="num_workers_tc06 must be at least 2"):
            AssessmentRunner(num_workers_tc06=1)

        with pytest.raises(ValueError, match="tampered_amount_tc07 must be a positive integer"):
            AssessmentRunner(tampered_amount_tc07=-5)

    def test_run_scenario_catches_unhandled_exceptions(self) -> None:
        """An unexpected scenario exception does not crash the orchestrator; returns ERROR result."""
        runner = AssessmentRunner()
        with patch.object(runner, "_get_scenario_dispatch") as mock_dispatch:
            def raise_crash():
                raise RuntimeError("Simulated network stack crash")

            mock_dispatch.return_value = {"TC-01": raise_crash}
            result = runner.run_scenario("TC-01")

            assert result.scenario_id == "TC-01"
            assert result.status == "ERROR"
            assert "Simulated network stack crash" in result.error
            assert result.duration_ms >= 0

    def test_run_scenario_unknown_id_raises_value_error(self) -> None:
        """Invoking an invalid scenario ID raises ValueError."""
        runner = AssessmentRunner()
        with pytest.raises(ValueError, match="Unknown scenario ID 'TC-99'"):
            runner.run_scenario("TC-99")

    def test_run_all_sequential_orchestration(self) -> None:
        """Verify run_all iterates sequentially across all 7 scenarios in exact order."""
        runner = AssessmentRunner()
        executed_order: list[str] = []
        progress_calls: list[str] = []

        def mock_scenario_func(scen_id: str):
            def _runner():
                executed_order.append(scen_id)
                return ScenarioResult(
                    scenario_id=scen_id,
                    scenario_name=f"Scenario {scen_id}",
                    status="PASS",
                    expected_behavior="Expected",
                    actual_behavior="Actual",
                )
            return _runner

        mock_dispatch = {
            scen_id: mock_scenario_func(scen_id)
            for scen_id in AssessmentRunner.ORDERED_SCENARIO_IDS
        }

        with patch.object(runner, "_get_scenario_dispatch", return_value=mock_dispatch):
            def on_progress(sid, res):
                progress_calls.append(sid)

            summary = runner.run_all(mode="secure", progress_callback=on_progress)

            assert executed_order == list(AssessmentRunner.ORDERED_SCENARIO_IDS)
            assert progress_calls == list(AssessmentRunner.ORDERED_SCENARIO_IDS)
            assert summary.mode == "secure"
            assert len(summary.scenario_results) == 7
            assert len(summary.findings) == 0
            assert summary.pnri_score == 0.0
            assert summary.raw_risk_score == 0
            assert summary.is_complete is True
            assert summary.risk_band == "Low"

    def test_run_all_vulnerable_mode_summary(self) -> None:
        """Verify summary generation when all 7 scenarios detect vulnerabilities."""
        runner = AssessmentRunner()
        mock_dispatch = {
            scen_id: lambda s=scen_id: ScenarioResult(s, f"Scenario {s}", "FAIL", "E", "A")
            for scen_id in AssessmentRunner.ORDERED_SCENARIO_IDS
        }

        with patch.object(runner, "_get_scenario_dispatch", return_value=mock_dispatch):
            summary = runner.run_all(mode="vulnerable")

            assert summary.mode == "vulnerable"
            assert len(summary.scenario_results) == 7
            assert len(summary.findings) == 7
            assert summary.raw_risk_score == 125
            assert summary.pnri_score == 100.0
            assert summary.risk_band == "Critical"
            assert summary.completeness_pct == 100.0
            assert summary.is_complete is True


# ==============================================================================
# 4. CLI TESTS (run_assessment.py)
# ==============================================================================

class TestAssessmentCLI:
    """Validate CLI argument parsing, output formatting, and credential redaction."""

    def test_cli_requires_mode(self) -> None:
        """CLI without --mode exits with error code 2."""
        code = run_assessment.main([])
        assert code == 2

    def test_cli_rejects_invalid_mode(self) -> None:
        """CLI with invalid mode exits with error code 2."""
        code = run_assessment.main(["--mode", "invalid_mode"])
        assert code == 2

    def test_cli_rejects_non_positive_timeout(self) -> None:
        """CLI with non-positive timeout exits with error code 2."""
        code = run_assessment.main(["--mode", "secure", "--timeout", "-1"])
        assert code == 2

    def test_cli_single_scenario_execution(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI executing a single scenario prints progress and returns 0 on PASS."""
        mock_res = ScenarioResult("TC-01", "Payment Bypass", "PASS", "E", "Safe")
        with patch.object(AssessmentRunner, "run_scenario", return_value=mock_res):
            code = run_assessment.main(["--mode", "secure", "--scenario", "TC-01"])
            assert code == 0
            out = capsys.readouterr().out
            assert "TC-01" in out
            assert "[PASS]" in out

    def test_cli_full_run_and_credential_redaction(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI execution never leaks admin keys or credentials."""
        secret_key = "super-secret-admin-token-12345"
        mock_summary = AssessmentSummary(
            assessment_id="fg-test-01",
            target="http://127.0.0.1:5000",
            mode="secure",
            scenario_results=[ScenarioResult("TC-01", "TC-01", "PASS", "E", "A")],
            findings=[],
            raw_risk_score=0,
            pnri_score=0.0,
        )
        mock_summary.risk_band = "Low"
        mock_summary.completeness_pct = 100.0

        with patch.object(AssessmentRunner, "run_all", return_value=mock_summary):
            code = run_assessment.main([
                "--mode", "secure",
                "--admin-key", secret_key,
            ])
            assert code == 0
            captured = capsys.readouterr()
            assert secret_key not in captured.out
            assert secret_key not in captured.err
            assert "PNRI Score     : 0.00 / 100.00 (Low Risk)" in captured.out

    def test_cli_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI --json outputs valid JSON string."""
        mock_summary = AssessmentSummary(
            assessment_id="fg-test-json",
            target="http://127.0.0.1:5000",
            mode="vulnerable",
            scenario_results=[],
            findings=[],
            raw_risk_score=0,
            pnri_score=0.0,
        )
        with patch.object(AssessmentRunner, "run_all", return_value=mock_summary):
            code = run_assessment.main(["--mode", "vulnerable", "--json"])
            assert code == 0
            out = capsys.readouterr().out
            parsed = json.loads(out)
            assert parsed["assessment_id"] == "fg-test-json"
            assert parsed["mode"] == "vulnerable"
            assert "pnri_score" in parsed


# ==============================================================================
# 5. LIVE INTEGRATION TESTS AGAINST SHOPZONE ROUTES
# ==============================================================================

class TransportResponse:
    """Minimal requests-compatible response container."""

    def __init__(self, status_code: int, payload: object, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {"Content-Type": "application/json"}
        self.reason = "OK" if status_code < 400 else "Error"
        self.text = json.dumps(payload) if not isinstance(payload, str) else payload

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("Invalid JSON")
        return self._payload


class FlaskRequestsSession:
    """Route Requests calls through Flask test client in-process."""

    def __init__(self, flask_client) -> None:
        self.flask_client = flask_client
        self.trust_env = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def request(self, *, method, url, json=None, params=None, headers=None, timeout=None, allow_redirects=True):
        parsed = urlsplit(url)
        path = parsed.path
        response = self.flask_client.open(path, method=method, json=json, headers=headers)
        return TransportResponse(
            response.status_code,
            response.get_json(silent=True) if response.is_json else response.get_data(as_text=True),
            {"Content-Type": response.content_type},
        )


class ControlledPhaseAHook:
    """Synchronize concurrent checkout workers at a barrier for deterministic race testing."""

    def __init__(self, num_parties: int, timeout: float = 3.0) -> None:
        import threading
        self.barrier = threading.Barrier(num_parties)
        self.num_parties = num_parties
        self.timeout = timeout
        self.counter = 0
        self.lock = threading.Lock()

    def __call__(self) -> None:
        with self.lock:
            self.counter += 1
            should_wait = (self.counter <= self.num_parties)

        if should_wait:
            try:
                self.barrier.wait(timeout=self.timeout)
            except Exception:
                pass


class TestLiveShopZoneIntegration:
    """Verify live scenario execution and result aggregation against in-memory Flask testing client."""

    def test_runner_live_secure_mode_full_suite(self, client) -> None:
        """Full suite execution against secure ShopZone routes yields 0 findings and 0.0 PNRI."""
        config = FlowGuardConfig(
            base_url="http://127.0.0.1:5000",
            target_mode="secure",
            admin_key=TestingConfig.ADMIN_KEY,
        )
        runner = AssessmentRunner(config, timeout=2.0)

        def session_factory():
            return FlaskRequestsSession(client)

        with patch("requests.Session", side_effect=session_factory):
            summary = runner.run_all(mode="secure")

            assert summary.mode == "secure"
            assert len(summary.scenario_results) == 7
            for res in summary.scenario_results:
                assert res.status == "PASS", f"Scenario {res.scenario_id} unexpectedly failed: {res.actual_behavior}"

            assert len(summary.findings) == 0
            assert summary.raw_risk_score == 0
            assert summary.pnri_score == 0.0
            assert summary.risk_band == "Low"
            assert summary.completeness_pct == 100.0
            assert summary.is_complete is True

    def test_runner_live_vulnerable_mode_full_suite(self, client) -> None:
        """Full suite execution against vulnerable ShopZone routes detects all 7 vulnerabilities."""
        from shopzone.blueprints.vulnerable.vuln_orders import set_checkout_race_hook

        config = FlowGuardConfig(
            base_url="http://127.0.0.1:5000",
            target_mode="vulnerable",
            admin_key=TestingConfig.ADMIN_KEY,
        )
        runner = AssessmentRunner(config, timeout=2.0)

        def session_factory():
            return FlaskRequestsSession(client)

        def on_progress(scen_id: str, res: ScenarioResult) -> None:
            # Set race hook right before TC-06 starts and clear it immediately after
            if scen_id == "TC-05":
                set_checkout_race_hook(ControlledPhaseAHook(num_parties=4))
            elif scen_id == "TC-06":
                set_checkout_race_hook(None)

        try:
            with patch("requests.Session", side_effect=session_factory):
                summary = runner.run_all(mode="vulnerable", progress_callback=on_progress)

                assert summary.mode == "vulnerable"
                assert len(summary.scenario_results) == 7
                for res in summary.scenario_results:
                    assert res.status == "FAIL", f"Scenario {res.scenario_id} did not detect vulnerability: {res.actual_behavior}"

                assert len(summary.findings) == 7
                assert summary.raw_risk_score == 125
                assert summary.pnri_score == 100.0
                assert summary.risk_band == "Critical"
                assert summary.completeness_pct == 100.0
                assert summary.is_complete is True
        finally:
            set_checkout_race_hook(None)
