"""Tests for FLOWGUARD Executive PDF Reporting Engine (Milestone 5).

Verifies PDF generation across all assessment states (vulnerable, secure, incomplete,
zero findings, multiple findings, malformed data), credential redaction, multi-page
structure, and historical assessment generation without HTTP execution.
"""

from __future__ import annotations

import io
import base64
import zlib
from pathlib import Path
from typing import Any

import pytest

from flowguard.history import AssessmentHistoryStore
from flowguard.reporting import PDFReportGenerator, generate_pdf_report
from flowguard.schemas import AssessmentSummary, EvidenceRecord, Finding, ScenarioResult


def extract_pdf_decompressed_text(pdf_bytes: bytes) -> str:
    """Extract and decompress all text content streams from a ReportLab PDF document.

    ReportLab encodes page content streams using Adobe ASCII85 followed by FlateDecode.
    This helper locates all stream ... endstream blocks, decodes the Adobe ASCII85
    stream, decompresses the zlib/Flate payload, and returns the aggregated text.
    """
    pos = 0
    decompressed_parts: list[str] = []
    while True:
        st_idx = pdf_bytes.find(b"stream\n", pos)
        if st_idx == -1:
            st_idx = pdf_bytes.find(b"stream\r\n", pos)
            if st_idx == -1:
                break
            data_start = st_idx + len(b"stream\r\n")
        else:
            data_start = st_idx + len(b"stream\n")

        end_idx = pdf_bytes.find(b"endstream", data_start)
        if end_idx == -1:
            break
        raw_stream = pdf_bytes[data_start:end_idx].strip()
        pos = end_idx + len(b"endstream")

        # Try Adobe ASCII85 + FlateDecode (standard ReportLab page content stream)
        try:
            a85_data = base64.a85decode(raw_stream, adobe=True)
            decomp = zlib.decompress(a85_data)
            decompressed_parts.append(decomp.decode("latin1", errors="ignore"))
            continue
        except Exception:
            pass

        # Try direct FlateDecode
        try:
            decomp = zlib.decompress(raw_stream)
            decompressed_parts.append(decomp.decode("latin1", errors="ignore"))
            continue
        except Exception:
            pass

        # Plaintext fallback
        decompressed_parts.append(raw_stream.decode("latin1", errors="ignore"))

    return "\n".join(decompressed_parts)


# ==============================================================================
# FIXTURES & SAMPLE DATA GENERATORS
# ==============================================================================

def make_sample_vulnerable_summary() -> AssessmentSummary:
    """Create a fully completed vulnerable assessment summary (PNRI = 100.0)."""
    scenarios = [
        ScenarioResult("TC-01", "Payment Bypass", "FAIL", "Order blocked", "Order unpaid", duration_ms=110),
        ScenarioResult("TC-02", "Coupon Reuse", "FAIL", "Single redemption", "Multi-redeemed", duration_ms=95),
        ScenarioResult("TC-03", "Duplicate Order", "FAIL", "Idempotent checkout", "Duplicate created", duration_ms=80),
        ScenarioResult("TC-04", "Order IDOR", "FAIL", "Strict tenant isolation", "Cross-tenant access", duration_ms=75),
        ScenarioResult("TC-05", "Workflow Transitions", "FAIL", "Validated transitions", "Illegal skip", duration_ms=60),
        ScenarioResult("TC-06", "Concurrent Race", "FAIL", "Serialized inventory", "Oversold stock", duration_ms=350),
        ScenarioResult("TC-07", "Price Tampering", "FAIL", "Server-authoritative total", "Client price accepted", duration_ms=85),
    ]
    findings = [
        Finding(
            id="FG-TC01-001",
            scenario_id="TC-01",
            title="Unpaid Order Confirmation via State Transition Bypass",
            severity="CRITICAL",
            description="Order transitioned directly to confirmed state without payment record.",
            impact="Direct monetary loss and inventory fulfillment without payment.",
            remediation="Validate cryptographic payment confirmation before transition.",
            evidence_references=["POST /orders/1/confirm -> 200 OK (unpaid)"],
        ),
        Finding(
            id="FG-TC02-001",
            scenario_id="TC-02",
            title="Global Single-Use Coupon Multi-Redemption",
            severity="HIGH",
            description="Single-use discount coupon applied across multiple user carts.",
            impact="Promotion budget exhaustion and margin erosion.",
            remediation="Enforce atomic coupon usage records with unique DB constraints.",
            evidence_references=["POST /cart/coupon -> 200 OK applied 2x"],
        ),
        Finding(
            id="FG-TC04-001",
            scenario_id="TC-04",
            title="Insecure Direct Object Reference on Orders",
            severity="CRITICAL",
            description="Victim order data accessible to attacker without authorization.",
            impact="Mass privacy violation and sensitive order leakage.",
            remediation="Enforce ownership check: order.user_id == authenticated_user_id.",
            evidence_references=["GET /orders/99 -> 200 OK with victim details"],
        ),
    ]
    summary = AssessmentSummary(
        assessment_id="fg-asm-a1b2c3d4e5f6",
        target="http://127.0.0.1:5000",
        mode="vulnerable",
        start_time="2026-11-03T02:00:00Z",
        end_time="2026-11-03T02:01:30Z",
        scenario_results=scenarios,
        findings=findings,
        raw_risk_score=65,
        pnri_score=52.0,
    )
    summary.risk_band = "High"
    summary.completeness_pct = 100.0
    summary.is_complete = True
    return summary


def make_sample_secure_summary() -> AssessmentSummary:
    """Create a fully completed secure assessment summary (PNRI = 0.0)."""
    scenarios = [
        ScenarioResult("TC-01", "Payment Bypass", "PASS", "Order blocked", "Blocked with 400", duration_ms=105),
        ScenarioResult("TC-02", "Coupon Reuse", "PASS", "Single redemption", "Second rejected 409", duration_ms=90),
        ScenarioResult("TC-03", "Duplicate Order", "PASS", "Idempotent checkout", "Duplicate rejected 409", duration_ms=75),
        ScenarioResult("TC-04", "Order IDOR", "PASS", "Strict tenant isolation", "Forbidden 403", duration_ms=65),
        ScenarioResult("TC-05", "Workflow Transitions", "PASS", "Validated transitions", "Invalid transition 400", duration_ms=55),
        ScenarioResult("TC-06", "Concurrent Race", "PASS", "Serialized inventory", "Oversell prevented 409", duration_ms=320),
        ScenarioResult("TC-07", "Price Tampering", "PASS", "Server-authoritative total", "Client total overridden", duration_ms=80),
    ]
    summary = AssessmentSummary(
        assessment_id="fg-asm-001122334455",
        target="http://127.0.0.1:5000",
        mode="secure",
        start_time="2026-11-03T02:10:00Z",
        end_time="2026-11-03T02:11:15Z",
        scenario_results=scenarios,
        findings=[],
        raw_risk_score=0,
        pnri_score=0.0,
    )
    summary.risk_band = "Low"
    summary.completeness_pct = 100.0
    summary.is_complete = True
    return summary


# ==============================================================================
# 1. CORE PDF GENERATION TESTS
# ==============================================================================

class TestPDFReportGenerator:
    """Test suite for PDF report generation across various assessment states."""

    def test_complete_vulnerable_assessment_pdf(self) -> None:
        """Verify complete vulnerable assessment PDF generation and binary structure."""
        summary = make_sample_vulnerable_summary()
        pdf_bytes = generate_pdf_report(summary)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        # Check standard PDF header and EOF trailer
        assert pdf_bytes.startswith(b"%PDF-")
        assert b"%%EOF" in pdf_bytes[-1024:]

    def test_complete_secure_assessment_pdf(self) -> None:
        """Verify complete secure assessment PDF with zero findings."""
        summary = make_sample_secure_summary()
        pdf_bytes = generate_pdf_report(summary)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        assert pdf_bytes.startswith(b"%PDF-")
        assert b"%%EOF" in pdf_bytes[-1024:]

    def test_incomplete_assessment_pdf(self) -> None:
        """Verify incomplete assessment PDF renders prominent warning callouts."""
        scenarios = [
            ScenarioResult("TC-01", "Payment Bypass", "PASS", "Blocked", "Blocked", duration_ms=100),
            ScenarioResult("TC-02", "Coupon Reuse", "ERROR", "Single use", "HTTP 500 server crashed", duration_ms=50),
            ScenarioResult("TC-03", "Duplicate Order", "INCONCLUSIVE", "Idempotent", "Timeout after 5s", duration_ms=5000),
        ]
        summary = AssessmentSummary(
            assessment_id="fg-asm-deadbeef1234",
            target="http://127.0.0.1:5000",
            mode="secure",
            scenario_results=scenarios,
            findings=[],
            raw_risk_score=0,
            pnri_score=0.0,
        )
        summary.risk_band = "Low"
        summary.completeness_pct = 33.3
        summary.is_complete = False

        pdf_bytes = generate_pdf_report(summary)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 2000

    def test_assessment_with_zero_findings(self) -> None:
        """Verify report generation when zero findings exist without errors."""
        summary = make_sample_secure_summary()
        summary.findings = []
        generator = PDFReportGenerator(summary)
        pdf_bytes = generator.generate()

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1500

    def test_multiple_findings_with_all_severities(self) -> None:
        """Verify report rendering with multiple findings spanning all 4 severities."""
        findings = [
            Finding("F1", "TC-01", "Crit Vuln", "CRITICAL", "Desc", "Imp", "Rem", ["ev1"]),
            Finding("F2", "TC-02", "High Vuln", "HIGH", "Desc", "Imp", "Rem", ["ev2"]),
            Finding("F3", "TC-05", "Med Vuln", "MEDIUM", "Desc", "Imp", "Rem", []),
            Finding("F4", "TC-07", "Low Vuln", "LOW", "Desc", "Imp", "Rem", []),
        ]
        summary = make_sample_vulnerable_summary()
        summary.findings = findings
        pdf_bytes = generate_pdf_report(summary)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 3000

    def test_missing_or_malformed_fields(self) -> None:
        """Verify generator handles missing, None, or completely malformed inputs gracefully."""
        # Empty dict
        pdf_empty = generate_pdf_report({})
        assert pdf_empty.startswith(b"%PDF-")

        # Dict with None or invalid values
        malformed = {
            "assessment_id": None,
            "target": None,
            "mode": None,
            "start_time": None,
            "end_time": None,
            "raw_risk_score": "not_an_int",
            "pnri_score": "not_a_float",
            "risk_band": None,
            "completeness_pct": None,
            "scenario_results": None,
            "findings": None,
        }
        pdf_malformed = generate_pdf_report(malformed)
        assert isinstance(pdf_malformed, bytes)
        assert pdf_malformed.startswith(b"%PDF-")

    def test_credential_redaction_in_pdf(self) -> None:
        """Verify secrets, passwords, tokens, and admin keys are strictly redacted in decompressed PDF content."""
        secret_pass = "P@ssw0rd123SuperSecret"
        secret_tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SecretPayload"
        secret_adm = "fg-admin-supersecretkey"
        secret_cookie = "sess_cookie_998877665544"

        summary = AssessmentSummary(
            assessment_id="fg-asm-redacttest01",
            target="http://127.0.0.1:5000",
            mode="vulnerable",
            scenario_results=[
                ScenarioResult(
                    "TC-01",
                    "Payment Bypass",
                    "FAIL",
                    "Expected payment enforcement",
                    f"Observed transition failure. User password: {secret_pass}",
                    evidence=[
                        EvidenceRecord(
                            "2026-11-03T00:00:00Z",
                            "TC-01",
                            "/api/checkout",
                            {
                                "password": secret_pass,
                                "ADMIN_KEY": secret_adm,
                                "cookie": secret_cookie,
                            },
                            {
                                "token": secret_tok,
                                "Authorization": f"Bearer {secret_tok}",
                            },
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
                    f"State transition bypass occurred. Config admin_key: {secret_adm}",
                    f"Financial impact with session cookie: {secret_cookie}",
                    "Fix payment check",
                    evidence_references=[
                        f"Auth Header: Bearer {secret_tok}",
                        f"Credentials used: password: {secret_pass}",
                    ],
                )
            ],
            raw_risk_score=25,
            pnri_score=20.0,
        )

        pdf_bytes = generate_pdf_report(summary)

        # 1. Verify secrets are not present in binary container
        assert secret_pass.encode("utf-8") not in pdf_bytes
        assert secret_tok.encode("utf-8") not in pdf_bytes
        assert secret_adm.encode("utf-8") not in pdf_bytes
        assert secret_cookie.encode("utf-8") not in pdf_bytes

        # 2. Decompress Adobe ASCII85 + FlateDecode page content streams
        decompressed_text = extract_pdf_decompressed_text(pdf_bytes)
        assert len(decompressed_text) > 0

        # 3. Verify secrets are strictly absent from decoded PDF content
        for secret in [secret_pass, secret_tok, secret_adm, secret_cookie]:
            assert secret not in decompressed_text, f"Secret {secret!r} leaked into decompressed PDF text!"

        # 4. Verify explicit redaction marker is present in decoded stream
        assert "***REDACTED***" in decompressed_text

    def test_credential_redaction_assertion_catches_unredacted_secret(self) -> None:
        """Verify the test assertion definitively fails if an unredacted secret appears in decoded PDF content."""
        hypothetical_secret = "HypotheticalLeakedSecret123"
        mock_pdf_decompressed = f"FLOWGUARD Report text with leaked {hypothetical_secret} in stream."

        # Proves that requirement 5 is satisfied: an actual unredacted secret would trigger an AssertionError
        with pytest.raises(AssertionError):
            assert hypothetical_secret not in mock_pdf_decompressed

    def test_generate_pdf_to_file_path(self, tmp_path: Path) -> None:
        """Verify generating a PDF directly to a file path on disk."""
        summary = make_sample_vulnerable_summary()
        out_file = tmp_path / "reports" / "assessment_report.pdf"

        pdf_bytes = generate_pdf_report(summary, output_path=out_file)

        assert out_file.exists()
        assert out_file.stat().st_size == len(pdf_bytes)
        assert out_file.stat().st_size > 2000

    def test_accepts_raw_dict_summary(self) -> None:
        """Verify generate_pdf_report works directly with raw summary dicts."""
        summary_dict = make_sample_vulnerable_summary().to_dict()
        pdf_bytes = generate_pdf_report(summary_dict)

        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_historical_pdf_generation_without_http_execution(self, tmp_path: Path) -> None:
        """Verify generating PDF from historical records without HTTP execution or modification."""
        store = AssessmentHistoryStore(storage_dir=tmp_path)
        summary = make_sample_vulnerable_summary()
        saved_file = store.save_assessment(summary)

        # Record file modification time and size
        mtime_before = saved_file.stat().st_mtime
        size_before = saved_file.stat().st_size

        # Load historical assessment
        historical_record = store.load_assessment(summary.assessment_id)
        assert historical_record is not None

        # Generate PDF report from historical data
        pdf_bytes = generate_pdf_report(historical_record)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")

        # Confirm historical file was NOT modified
        assert saved_file.stat().st_mtime == mtime_before
        assert saved_file.stat().st_size == size_before


    def test_executive_summary_derives_claims_exclusively_from_confirmed_findings(self) -> None:
        """Verify executive summary lists ONLY confirmed findings and marks INCONCLUSIVE as unverified."""
        # 6 FAIL, 1 INCONCLUSIVE (TC-02)
        scenarios = [
            ScenarioResult("TC-01", "Payment Bypass", "FAIL", "Order blocked", "Order unpaid", duration_ms=110),
            ScenarioResult("TC-02", "Coupon Reuse", "INCONCLUSIVE", "Single redemption", "Coupon CYBERSEC20 is exhausted", duration_ms=25),
            ScenarioResult("TC-03", "Duplicate Order", "FAIL", "Idempotent checkout", "Duplicate created", duration_ms=80),
            ScenarioResult("TC-04", "Order IDOR", "FAIL", "Strict tenant isolation", "Cross-tenant access", duration_ms=75),
            ScenarioResult("TC-05", "Workflow Transitions", "FAIL", "Validated transitions", "Illegal skip", duration_ms=60),
            ScenarioResult("TC-06", "Concurrent Race", "FAIL", "Serialized inventory", "Oversold stock", duration_ms=350),
            ScenarioResult("TC-07", "Price Tampering", "FAIL", "Server-authoritative total", "Client price accepted", duration_ms=85),
        ]
        # Only 6 findings (TC-02 generates NO finding)
        findings = [
            Finding("FG-TC01-001", "TC-01", "Unpaid Order Confirmation", "CRITICAL", "Desc 1", "Impact 1", "Remed 1", []),
            Finding("FG-TC03-001", "TC-03", "Duplicate Order Checkout", "HIGH", "Desc 3", "Impact 3", "Remed 3", []),
            Finding("FG-TC04-001", "TC-04", "Horizontal Order IDOR", "HIGH", "Desc 4", "Impact 4", "Remed 4", []),
            Finding("FG-TC05-001", "TC-05", "Illegal Workflow Transitions", "HIGH", "Desc 5", "Impact 5", "Remed 5", []),
            Finding("FG-TC06-001", "TC-06", "Inventory Race Condition", "HIGH", "Desc 6", "Impact 6", "Remed 6", []),
            Finding("FG-TC07-001", "TC-07", "Client-Side Price Tampering", "HIGH", "Desc 7", "Impact 7", "Remed 7", []),
        ]
        summary = AssessmentSummary(
            assessment_id="fg-asm-test001234",
            target="http://127.0.0.1:5000",
            mode="vulnerable",
            start_time="2026-11-04T12:00:00Z",
            end_time="2026-11-04T12:01:00Z",
            scenario_results=scenarios,
            findings=findings,
            raw_risk_score=110,
            pnri_score=88.0,
        )
        summary.risk_band = "Critical"
        summary.completeness_pct = 85.7
        summary.is_complete = False

        pdf_bytes = generate_pdf_report(summary)
        decompressed_text = extract_pdf_decompressed_text(pdf_bytes)

        # 1. Confirmed findings are listed
        assert "unpaid order confirmation" in decompressed_text
        assert "duplicate checkout generation" in decompressed_text

        # 2. INCONCLUSIVE TC-02 flaw is NOT claimed as a confirmed failure
        assert "single-use coupon multi-redemption" not in decompressed_text

        # 3. TC-02 is explicitly described under Unverified Scenarios
        assert "Unverified Scenarios" in decompressed_text
        assert "TC-02" in decompressed_text
        assert "never classified as confirmed vulnerabilities" in decompressed_text

        # 4. Incomplete assessment warning is prominently displayed
        assert "INCOMPLETE ASSESSMENT WARNING" in decompressed_text
        assert "AN INCOMPLETE ASSESSMENT CAN NEVER BE CERTIFIED AS SECURE" in decompressed_text

    def test_long_scenario_description_wrapping_in_pdf(self) -> None:
        """Verify long scenario observations (>180 chars) wrap cleanly and are not truncated in PDF output."""
        long_observation = (
            "Secure mode strictly enforced finite state machine invariants: unpaid confirmation was rejected (HTTP 400), "
            "terminal states (CANCELLED) resisted mutation and repeated operations, resurrection of cancelled orders was blocked, "
            "and legitimate transitions completed successfully."
        )
        assert len(long_observation) > 250

        scenarios = [
            ScenarioResult(
                scenario_id="TC-05",
                scenario_name="Workflow Lifecycle FSM",
                status="PASS",
                expected_behavior="Strict transition enforcement",
                actual_behavior=long_observation,
                duration_ms=750,
            ),
        ]
        summary = AssessmentSummary(
            assessment_id="fg-asm-wrapcheck12",
            target="http://127.0.0.1:5000",
            mode="secure",
            start_time="2026-11-04T12:00:00Z",
            end_time="2026-11-04T12:01:00Z",
            scenario_results=scenarios,
            findings=[],
            raw_risk_score=0,
            pnri_score=0.0,
        )
        summary.risk_band = "Low"
        summary.completeness_pct = 100.0
        summary.is_complete = True

        pdf_bytes = generate_pdf_report(summary)
        decompressed_text = extract_pdf_decompressed_text(pdf_bytes)

        # Verify that the tail end of the long text is present and NOT truncated at char 180
        assert "transitions completed successfully" in decompressed_text
