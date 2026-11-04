"""Assessment Orchestrator for FLOWGUARD.

Sequentially executes TC-01 through TC-07, maps confirmed vulnerabilities into
canonical security findings, and calculates the PNRI risk score.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .client import FlowGuardClient
from .config import FlowGuardConfig
from .findings import extract_findings_from_results
from .schemas import AssessmentSummary, ScenarioResult
from .scoring import calculate_pnri
from .scenarios.tc01_payment_bypass import TC01PaymentBypassScenario
from .scenarios.tc02_coupon_reuse import TC02CouponReuseScenario
from .scenarios.tc03_duplicate_order import TC03DuplicateOrderScenario
from .scenarios.tc04_order_idor import TC04OrderIDORScenario
from .scenarios.tc05_invalid_workflow import TC05InvalidWorkflowScenario
from .scenarios.tc06_concurrent_checkout import TC06ConcurrentCheckoutScenario
from .scenarios.tc07_price_tampering import TC07PriceTamperingScenario


class AssessmentRunner:
    """Orchestrates end-to-end FLOWGUARD assessment runs across all 7 scenarios."""

    ORDERED_SCENARIO_IDS: tuple[str, ...] = (
        "TC-01",
        "TC-02",
        "TC-03",
        "TC-04",
        "TC-05",
        "TC-06",
        "TC-07",
    )

    def __init__(
        self,
        config: FlowGuardConfig | None = None,
        *,
        timeout: float = 5.0,
        coupon_code: str = "CYBERSEC20",
        num_workers_tc06: int = 4,
        tampered_amount_tc07: int = 100,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")
        if num_workers_tc06 < 2:
            raise ValueError("num_workers_tc06 must be at least 2.")
        if tampered_amount_tc07 <= 0:
            raise ValueError("tampered_amount_tc07 must be a positive integer.")

        self.config = config or FlowGuardConfig.from_env()
        self.timeout = timeout
        self.coupon_code = coupon_code
        self.num_workers_tc06 = num_workers_tc06
        self.tampered_amount_tc07 = tampered_amount_tc07
        self.client = FlowGuardClient(self.config)

    def _get_scenario_dispatch(
        self, selected_mode: str
    ) -> dict[str, Callable[[], ScenarioResult]]:
        """Return the dictionary of scenario runner callables."""
        return {
            "TC-01": lambda: TC01PaymentBypassScenario(
                self.client, timeout=self.timeout
            ).run(mode=selected_mode),
            "TC-02": lambda: self._run_tc02(selected_mode),
            "TC-03": lambda: TC03DuplicateOrderScenario(
                self.client, timeout=self.timeout
            ).run(mode=selected_mode),
            "TC-04": lambda: TC04OrderIDORScenario(
                self.client, timeout=self.timeout
            ).run(mode=selected_mode),
            "TC-05": lambda: TC05InvalidWorkflowScenario(
                self.client, timeout=self.timeout
            ).run(mode=selected_mode),
            "TC-06": lambda: TC06ConcurrentCheckoutScenario(
                self.client, timeout=self.timeout
            ).run(mode=selected_mode, num_workers=self.num_workers_tc06),
            "TC-07": lambda: TC07PriceTamperingScenario(
                self.client, timeout=self.timeout
            ).run(mode=selected_mode, tampered_amount=self.tampered_amount_tc07),
        }

    def _run_tc02(self, selected_mode: str) -> ScenarioResult:
        """Execute TC-02 with unique synthetic coupon provisioning for repeatable assessments."""
        coupon_to_use = self.coupon_code
        if (self.coupon_code == "CYBERSEC20" or not self.coupon_code) and self.config.admin_key:
            synth_code = f"SYNTH_CPN_{uuid.uuid4().hex[:8].upper()}"
            prov_res = self.client.post(
                f"/api/admin/coupon/{selected_mode}",
                headers={"X-Admin-Key": self.config.admin_key},
                json={"code": synth_code, "discount_pct": 20, "max_uses": 1},
                timeout=self.timeout,
            )
            if prov_res.status_code in (200, 201):
                coupon_to_use = synth_code
        return TC02CouponReuseScenario(self.client, timeout=self.timeout).run(
            mode=selected_mode, coupon_code=coupon_to_use
        )

    def run_scenario(self, scenario_id: str, mode: str | None = None) -> ScenarioResult:
        """Execute a single scenario with guarded exception handling."""
        selected_mode = (mode or self.config.target_mode).lower()
        scen_id = scenario_id.strip().upper()
        dispatch = self._get_scenario_dispatch(selected_mode)

        if scen_id not in dispatch:
            raise ValueError(
                f"Unknown scenario ID '{scenario_id}'. Supported: {list(self.ORDERED_SCENARIO_IDS)}"
            )

        start_time = time.perf_counter()
        try:
            result = dispatch[scen_id]()
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ScenarioResult(
                scenario_id=scen_id,
                scenario_name=f"Scenario {scen_id}",
                status="ERROR",
                expected_behavior="Normal scenario execution.",
                actual_behavior="Unhandled exception during scenario execution.",
                error=f"{type(exc).__name__}: {str(exc)}",
                duration_ms=duration_ms,
            )

        return result

    def run_all(
        self,
        mode: str | None = None,
        *,
        progress_callback: Callable[[str, ScenarioResult], None] | None = None,
    ) -> AssessmentSummary:
        """Sequentially execute all 7 scenarios and assemble the AssessmentSummary.

        Args:
            mode: Target mode ('vulnerable' or 'secure'). Defaults to config.target_mode.
            progress_callback: Optional callback invoked as (scenario_id, result) after each scenario.

        Returns:
            Populated AssessmentSummary containing results, findings, PNRI score, and metadata.
        """
        selected_mode = (mode or self.config.target_mode).lower()
        if selected_mode not in ("vulnerable", "secure"):
            raise ValueError("mode must be either 'vulnerable' or 'secure'.")

        assessment_id = f"fg-asm-{uuid.uuid4().hex[:12]}"
        start_time_iso = datetime.now(timezone.utc).isoformat()
        scenario_results: list[ScenarioResult] = []

        # Execute all scenarios strictly sequentially to protect database transactions
        for scen_id in self.ORDERED_SCENARIO_IDS:
            result = self.run_scenario(scen_id, mode=selected_mode)
            scenario_results.append(result)
            if progress_callback is not None:
                try:
                    progress_callback(scen_id, result)
                except Exception:
                    pass  # Never allow a UI/CLI callback error to abort assessment

        end_time_iso = datetime.now(timezone.utc).isoformat()

        # Map confirmed vulnerabilities (status == 'FAIL') to canonical findings
        findings = extract_findings_from_results(scenario_results)

        # Compute PNRI risk score and completeness
        pnri_result = calculate_pnri(
            confirmed_findings=findings,
            scenario_results=scenario_results,
            total_expected_scenarios=len(self.ORDERED_SCENARIO_IDS),
        )

        summary = AssessmentSummary(
            assessment_id=assessment_id,
            target=self.config.base_url,
            mode=selected_mode,
            start_time=start_time_iso,
            end_time=end_time_iso,
            scenario_results=scenario_results,
            findings=findings,
            raw_risk_score=pnri_result.raw_score,
            pnri_score=pnri_result.pnri_score,
        )

        # Attach extended metadata for dashboard/CLI export
        summary.risk_band = pnri_result.risk_band
        summary.completeness_pct = pnri_result.completeness_pct
        summary.is_complete = pnri_result.is_complete
        summary.conclusive_count = pnri_result.conclusive_scenarios
        summary.inconclusive_count = pnri_result.inconclusive_scenarios
        summary.error_count = pnri_result.error_scenarios

        return summary
