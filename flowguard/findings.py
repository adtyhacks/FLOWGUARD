"""Canonical security finding definitions and factory for FLOWGUARD."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .schemas import Finding, ScenarioResult


@dataclass(frozen=True)
class FindingDefinition:
    """Canonical definition and template for a known security finding."""

    scenario_id: str
    finding_id: str
    title: str
    severity: str
    cwe_id: str
    cwe_name: str
    description: str
    impact: str
    remediation: str

    def create_finding(self, evidence_references: list[str] | None = None) -> Finding:
        """Instantiate a typed Finding schema instance."""
        # Include CWE reference directly in description for seamless export compatibility
        full_description = f"{self.description}\nCWE: {self.cwe_id} ({self.cwe_name})"
        return Finding(
            id=self.finding_id,
            scenario_id=self.scenario_id,
            title=self.title,
            severity=self.severity,
            description=full_description,
            impact=self.impact,
            remediation=self.remediation,
            evidence_references=evidence_references or [],
        )


# Canonical registry of all 7 FLOWGUARD security findings
CANONICAL_FINDINGS: dict[str, FindingDefinition] = {
    "TC-01": FindingDefinition(
        scenario_id="TC-01",
        finding_id="FG-TC01-001",
        title="Unpaid Order Confirmation via State Transition Bypass",
        severity="CRITICAL",
        cwe_id="CWE-840",
        cwe_name="Business Logic Errors",
        description=(
            "The order confirmation endpoint allows an order in PENDING_PAYMENT state "
            "to transition directly to CONFIRMED without requiring or validating a corresponding "
            "successful payment record."
        ),
        impact=(
            "Attackers can obtain goods or services without fulfilling monetary payment obligations, "
            "leading to direct financial loss and uncollectible inventory fulfillment."
        ),
        remediation=(
            "Require authoritative payment verification before allowing order status transitions. "
            "Validate that a completed payment record exists and is cryptographically tied to the order ID."
        ),
    ),
    "TC-02": FindingDefinition(
        scenario_id="TC-02",
        finding_id="FG-TC02-001",
        title="Global Single-Use Coupon Multi-Redemption",
        severity="HIGH",
        cwe_id="CWE-799",
        cwe_name="Improper Control of Generation of Multiple Requests",
        description=(
            "The checkout service fails to enforce atomic single-use restrictions on promotional "
            "coupons across multiple accounts or checkout sessions, permitting a single-use coupon "
            "to be redeemed repeatedly."
        ),
        impact=(
            "Multiple users can exhaust promotional discount budgets or apply unauthorized discounts "
            "repeatedly, eroding profit margins."
        ),
        remediation=(
            "Enforce atomic coupon redemption checks using database transactions and unique constraints. "
            "Mark coupons as redeemed within the same transaction that finalizes the order."
        ),
    ),
    "TC-03": FindingDefinition(
        scenario_id="TC-03",
        finding_id="FG-TC03-001",
        title="Checkout Replay Vulnerability / Lack of Idempotency Enforcement",
        severity="HIGH",
        cwe_id="CWE-294",
        cwe_name="Authentication Bypass by Capture-replay",
        description=(
            "The checkout endpoint does not enforce idempotency keys, allowing sequential replayed "
            "checkout requests with identical payload to generate duplicate orders and duplicate charges."
        ),
        impact=(
            "Network retries or replayed checkout submissions result in duplicate order fulfillment, "
            "unintended inventory allocation, and customer billing disputes."
        ),
        remediation=(
            "Implement idempotent request handling with a unique database constraint on the idempotency key. "
            "Return the cached order response for identical requests and HTTP 409 Conflict for mismatched payloads."
        ),
    ),
    "TC-04": FindingDefinition(
        scenario_id="TC-04",
        finding_id="FG-TC04-001",
        title="Insecure Direct Object Reference (IDOR) on Order Details",
        severity="CRITICAL",
        cwe_id="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        description=(
            "The order retrieval endpoint fails to enforce resource ownership validation, allowing "
            "any authenticated user to view complete order data and customer metadata belonging to another user."
        ),
        impact=(
            "Severe breach of customer confidentiality, unauthorized disclosure of PII, shipping addresses, "
            "purchased items, and transaction metadata to unprivileged tenants."
        ),
        remediation=(
            "Strictly enforce tenant authorization checks at the data layer (e.g. order.user_id == current_user.id). "
            "Return HTTP 403 or 404 for unauthorized access attempts without leaking order existence."
        ),
    ),
    "TC-05": FindingDefinition(
        scenario_id="TC-05",
        finding_id="FG-TC05-001",
        title="Illegal Order State Machine Transitions and Workflow Bypass",
        severity="HIGH",
        cwe_id="CWE-840",
        cwe_name="Business Logic Errors",
        description=(
            "The order workflow permits invalid state transitions, including confirming unpaid orders, "
            "resurrecting canceled orders, and applying conflicting state mutations out of sequence."
        ),
        impact=(
            "Order state machine corruption, inconsistent order statuses, bypassed operational controls, "
            "and unauthorized order fulfillment after cancellation."
        ),
        remediation=(
            "Implement a strict finite state machine (FSM) defining valid transitions (e.g., CART -> PENDING -> PAID -> CONFIRMED). "
            "Explicitly reject illegal transition attempts with HTTP 400 Bad Request."
        ),
    ),
    "TC-06": FindingDefinition(
        scenario_id="TC-06",
        finding_id="FG-TC06-001",
        title="Concurrent Checkout Race Condition Permitting Duplicate Order Creation",
        severity="HIGH",
        cwe_id="CWE-362",
        cwe_name="Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        description=(
            "The checkout endpoint is vulnerable to race conditions under concurrent execution. Simultaneous "
            "checkout requests bypass application-level uniqueness checks before transactions commit, "
            "creating duplicate orders from a single cart."
        ),
        impact=(
            "Inventory exhaustion, duplicate orders created without corresponding inventory or payment, "
            "and database state inconsistency under high load or adversarial concurrency."
        ),
        remediation=(
            "Enforce concurrency isolation using database row-level locking (SELECT FOR UPDATE), unique constraints "
            "on active carts/idempotency keys, or distributed locks around the checkout critical section."
        ),
    ),
    "TC-07": FindingDefinition(
        scenario_id="TC-07",
        finding_id="FG-TC07-001",
        title="Client-Side Order Total Parameter Tampering",
        severity="HIGH",
        cwe_id="CWE-602",
        cwe_name="Client-Side Enforcement of Server-Side Security",
        description=(
            "The checkout endpoint accepts and persists client-submitted order total parameters, overriding "
            "the authoritative server-side calculated pricing based on canonical product catalog unit prices."
        ),
        impact=(
            "Attackers can arbitrarily manipulate purchase prices (e.g., buying expensive merchandise for $1.00), "
            "causing catastrophic merchant revenue loss."
        ),
        remediation=(
            "Calculate all order prices, discounts, and totals exclusively on the server side using canonical "
            "catalog records. Completely ignore or reject client-supplied total_amount parameters."
        ),
    ),
}


def build_finding_from_scenario_result(result: ScenarioResult) -> Finding | None:
    """Build a canonical Finding if the scenario result indicates a confirmed vulnerability (status == FAIL).

    Returns:
        Finding instance if result.status == 'FAIL' and scenario_id is known; otherwise None.
    """
    if result.status != "FAIL":
        return None

    scen_id = result.scenario_id.upper()
    definition = CANONICAL_FINDINGS.get(scen_id)
    if definition is None:
        return None

    # Collect endpoints or step identifiers from evidence as references
    evidence_refs: list[str] = []
    if result.evidence:
        for idx, ev in enumerate(result.evidence):
            endpoint = getattr(ev, "endpoint", None) or (ev.get("endpoint") if isinstance(ev, dict) else "")
            if endpoint:
                evidence_refs.append(f"Step {idx + 1}: {endpoint}")

    return definition.create_finding(evidence_references=evidence_refs)


def extract_findings_from_results(results: Sequence[ScenarioResult]) -> list[Finding]:
    """Map a sequence of ScenarioResults into confirmed Finding objects."""
    findings: list[Finding] = []
    for result in results:
        finding = build_finding_from_scenario_result(result)
        if finding is not None:
            findings.append(finding)
    return findings
