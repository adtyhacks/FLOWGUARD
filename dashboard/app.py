"""FLOWGUARD — Streamlit Dashboard & Visual Analytics.

Interactive cybersecurity assessment dashboard for E-Commerce Business Logic
Security Verification, PNRI visualization, and Evidence Inspection.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import streamlit as st

# Ensure repository root is on sys.path for direct Streamlit execution
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT_DIR / ".env")
except ImportError:
    pass

from flowguard.config import FlowGuardConfig
from flowguard.history import AssessmentHistoryStore
from flowguard.reporting import generate_pdf_report
from flowguard.runner import AssessmentRunner
from flowguard.schemas import AssessmentSummary, ScenarioResult
from dashboard.charts import (
    create_pnri_gauge,
    create_scenario_status_chart,
    create_severity_breakdown_chart,
)


# ==============================================================================
# UI HELPERS & STYLING
# ==============================================================================

def get_status_badge(status: str) -> str:
    """Return an HTML badge representation of scenario invariant status."""
    status_upper = status.upper()
    if status_upper == "PASS":
        return '<span style="background-color:#28a745;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">PASS</span>'
    if status_upper == "FAIL":
        return '<span style="background-color:#dc3545;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">FAIL</span>'
    if status_upper == "ERROR":
        return '<span style="background-color:#ffc107;color:black;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">ERROR</span>'
    return '<span style="background-color:#6c757d;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">INCONCLUSIVE</span>'


def get_severity_badge(severity: str) -> str:
    """Return an HTML badge representation of finding severity."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return '<span style="background-color:#dc3545;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">CRITICAL</span>'
    if sev == "HIGH":
        return '<span style="background-color:#fd7e14;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">HIGH</span>'
    if sev == "MEDIUM":
        return '<span style="background-color:#ffc107;color:black;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">MEDIUM</span>'
    return '<span style="background-color:#17a2b8;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">LOW</span>'


# ==============================================================================
# MAIN STREAMLIT APPLICATION
# ==============================================================================

def main() -> None:
    st.set_page_config(
        page_title="FLOWGUARD — Business Logic Security Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Initialize session state keys
    if "is_running" not in st.session_state:
        st.session_state.is_running = False
    if "current_summary" not in st.session_state:
        st.session_state.current_summary = None
    if "active_tab" not in st.session_state:
        st.session_state.active_tab = 0

    history_store = AssessmentHistoryStore()

    # --------------------------------------------------------------------------
    # SIDEBAR CONTROLS
    # --------------------------------------------------------------------------
    with st.sidebar:
        st.title("🛡️ FLOWGUARD")
        st.caption("Business-Logic Assessment Platform")
        st.divider()

        st.subheader("Target Configuration")
        target_mode = st.selectbox(
            "Target Operating Mode",
            options=["vulnerable", "secure"],
            index=0,
            help="Select the target ShopZone mode: 'vulnerable' demonstrating flaws or 'secure' enforcing invariants.",
            disabled=st.session_state.is_running,
        )

        target_url = st.text_input(
            "Target Base URL",
            value=os.getenv("FLOWGUARD_BASE_URL", "http://127.0.0.1:5000"),
            help="Local ShopZone instance URL (strictly restricted to loopback/localhost).",
            disabled=st.session_state.is_running,
        )

        timeout = st.number_input(
            "HTTP Timeout (seconds)",
            min_value=1.0,
            max_value=30.0,
            value=float(os.getenv("FLOWGUARD_TIMEOUT", "5.0")),
            step=1.0,
            disabled=st.session_state.is_running,
        )

        admin_key = st.text_input(
            "Admin Verification Key",
            value=os.getenv("ADMIN_KEY", ""),
            type="password",
            help="X-Admin-Key for authoritative ground truth verification endpoints.",
            disabled=st.session_state.is_running,
        )

        st.divider()

        # Explicit run button (prevents auto-execution on page open)
        run_clicked = st.button(
            "🚀 Run Assessment",
            type="primary",
            use_container_width=True,
            disabled=st.session_state.is_running,
        )

        if run_clicked:
            st.session_state.is_running = True
            st.session_state.current_summary = None

        st.divider()
        st.caption("🔒 Security Enforcement:")
        st.caption("• Localhost target allowlist only")
        st.caption("• Sequential scenario execution")
        st.caption("• Automated credential redaction")
        st.caption("• Authoritative ground-truth validation")

    # --------------------------------------------------------------------------
    # ASSESSMENT EXECUTION HANDLER
    # --------------------------------------------------------------------------
    if st.session_state.is_running:
        with st.status("Executing Assessment Suite (Sequential)...", expanded=True) as status:
            try:
                config = FlowGuardConfig(
                    base_url=target_url,
                    target_mode=target_mode,
                    timeout=float(timeout),
                    admin_key=admin_key if admin_key else None,
                )
                runner = AssessmentRunner(config, timeout=float(timeout))

                progress_bar = st.progress(0, text="Initializing assessment...")
                scenario_count = len(AssessmentRunner.ORDERED_SCENARIO_IDS)
                completed = [0]

                def on_progress(sid: str, res: ScenarioResult) -> None:
                    completed[0] += 1
                    pct = int((completed[0] / scenario_count) * 100)
                    progress_bar.progress(pct, text=f"Executed {sid}: {res.status} ({res.duration_ms}ms)")

                summary = runner.run_all(mode=target_mode, progress_callback=on_progress)
                history_store.save_assessment(summary)
                st.session_state.current_summary = summary.to_dict()
                status.update(label="Assessment completed successfully!", state="complete", expanded=False)
            except Exception as exc:
                st.error(f"Assessment Execution Error: {exc}")
                status.update(label="Assessment execution failed.", state="error")
            finally:
                st.session_state.is_running = False
                st.rerun()

    # --------------------------------------------------------------------------
    # MAIN DASHBOARD CONTENT AREA
    # --------------------------------------------------------------------------
    summary_data = st.session_state.current_summary

    if not summary_data:
        # Initial Landing State (before any run has occurred in session)
        st.title("Business-Logic Security Assessment Dashboard")
        st.markdown(
            """
            Welcome to **FLOWGUARD**, the automated assessment platform for complex e-commerce
            business logic vulnerabilities and transactional invariants.

            ### Getting Started
            1. Verify the **Target Operating Mode** in the sidebar (`vulnerable` or `secure`).
            2. Click **🚀 Run Assessment** to execute the complete test suite.
            3. Or view historical assessments in the **Assessment History** tab below.
            """
        )

        past_runs = history_store.list_assessments()
        if past_runs:
            st.subheader("Recent Historical Assessments")
            for run in past_runs[:5]:
                col_btn, col_info, col_pdf = st.columns([1, 3.5, 1])
                with col_btn:
                    if st.button(f"Load {run['assessment_id'][:12]}", key=f"load_init_{run['assessment_id']}"):
                        loaded = history_store.load_assessment(run["assessment_id"])
                        if loaded:
                            st.session_state.current_summary = loaded
                            st.rerun()
                with col_info:
                    st.write(
                        f"**{run['mode'].upper()}** | PNRI: **{run['pnri_score']:.1f}%** ({run['risk_band']}) | "
                        f"Findings: {run['findings_count']} | {run['start_time'][:19]}"
                    )
                with col_pdf:
                    hist_data = history_store.load_assessment(run["assessment_id"])
                    if hist_data:
                        try:
                            pdf_b = generate_pdf_report(hist_data)
                            st.download_button(
                                label="📄 PDF",
                                data=pdf_b,
                                file_name=f"FLOWGUARD_Report_{run['assessment_id']}.pdf",
                                mime="application/pdf",
                                key=f"init_pdf_{run['assessment_id']}",
                            )
                        except Exception:
                            pass
        return

    # Extract summary metrics
    assessment_id = summary_data.get("assessment_id", "N/A")
    mode = summary_data.get("mode", "unknown").upper()
    start_time = summary_data.get("start_time", "N/A")
    raw_score = summary_data.get("raw_risk_score", 0)
    pnri_score = float(summary_data.get("pnri_score", 0.0))
    risk_band = summary_data.get("risk_band", "N/A")
    completeness = float(summary_data.get("completeness_pct", 100.0))
    is_complete = summary_data.get("is_complete", True)
    scenario_results = summary_data.get("scenario_results", [])
    findings = summary_data.get("findings", [])

    # Header section with PDF download & clear action
    header_col1, header_col2, header_col3 = st.columns([2.8, 1.4, 0.8])
    with header_col1:
        st.title(f"Assessment Report: {mode} Mode")
        st.caption(f"Assessment ID: `{assessment_id}` | Executed: `{start_time}` | Target: `{summary_data.get('target')}`")
    with header_col2:
        try:
            pdf_bytes = generate_pdf_report(summary_data)
            st.download_button(
                label="📄 Download PDF Report",
                data=pdf_bytes,
                file_name=f"FLOWGUARD_Report_{assessment_id}.pdf",
                mime="application/pdf",
                use_container_width=True,
                key="btn_download_current_pdf",
            )
        except Exception as exc:
            st.error(f"PDF Error: {exc}")
    with header_col3:
        if st.button("🔄 Clear", use_container_width=True):
            st.session_state.current_summary = None
            st.rerun()

    # Completeness Alert (Crucial security requirement: incomplete tests must never be disguised as clean)
    if not is_complete or completeness < 100.0:
        st.warning(
            f"⚠️ **INCOMPLETE ASSESSMENT WARNING**: Completeness is at **{completeness:.1f}%**. "
            "One or more scenarios concluded with ERROR or INCONCLUSIVE status. "
            "This target **CANNOT** be certified as secure until all invariants are definitively verified.",
            icon="⚠️",
        )

    # --------------------------------------------------------------------------
    # TABS: Overview | Scenarios | Findings | Evidence | History
    # --------------------------------------------------------------------------
    tab_overview, tab_scenarios, tab_findings, tab_evidence, tab_history = st.tabs([
        "📊 Executive Overview",
        "🎯 Scenario Matrix",
        f"🚨 Confirmed Findings ({len(findings)})",
        "🔍 Evidence Inspector",
        "📜 Assessment History",
    ])

    # ==========================================================================
    # TAB 1: EXECUTIVE OVERVIEW
    # ==========================================================================
    with tab_overview:
        # High-level metric cards
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("PNRI Score", f"{pnri_score:.1f}%", help="Platform-Normalized Risk Index (0.0 to 100.0)")
        m2.metric("Risk Classification", risk_band, help="Low (0-19.9), Moderate (20-49.9), High (50-74.9), Critical (75-100)")
        m3.metric("Raw Risk Score", f"{raw_score} / 125", help="Accumulated severity weights of confirmed findings")
        m4.metric("Completeness", f"{completeness:.1f}%", help="Percentage of test scenarios definitively concluded")
        m5.metric("Confirmed Flaws", len(findings), help="Total number of security invariant violations detected")

        st.divider()

        # Visual Analytics Charts
        chart_col1, chart_col2 = st.columns([1, 1])
        with chart_col1:
            st.plotly_chart(create_pnri_gauge(pnri_score, risk_band), use_container_width=True)
        with chart_col2:
            st.plotly_chart(create_severity_breakdown_chart(findings), use_container_width=True)

        st.subheader("Scenario Invariant Distribution")
        st.plotly_chart(create_scenario_status_chart(scenario_results), use_container_width=True)

    # ==========================================================================
    # TAB 2: SCENARIO MATRIX
    # ==========================================================================
    with tab_scenarios:
        st.subheader("Business Invariant Verification Status")
        st.caption("Each scenario validates a core e-commerce business logic invariant against authoritative ground truth.")

        status_filter = st.radio(
            "Filter Status:",
            options=["ALL", "FAIL", "PASS", "INCONCLUSIVE", "ERROR"],
            horizontal=True,
        )

        filtered_scenarios = [
            s for s in scenario_results
            if status_filter == "ALL" or s.get("status") == status_filter
        ]

        for s in filtered_scenarios:
            scen_id = s.get("scenario_id")
            name = s.get("scenario_name")
            status = s.get("status", "UNKNOWN")
            duration = s.get("duration_ms", 0)
            actual = s.get("actual_behavior", "")
            expected = s.get("expected_behavior", "")
            error = s.get("error")

            badge = get_status_badge(status)
            with st.expander(f"{scen_id} — {name} | {status} ({duration}ms)", expanded=(status == "FAIL")):
                c1, c2 = st.columns([1, 3])
                with c1:
                    st.markdown(f"**Status:** {badge}", unsafe_allow_html=True)
                    st.write(f"**Duration:** `{duration} ms`")
                with c2:
                    st.write(f"**Observed Behavior:** {actual}")
                    st.caption(f"**Expected Invariant:** {expected}")
                    if error:
                        st.error(f"Error Diagnostic: {error}")

    # ==========================================================================
    # TAB 3: CONFIRMED FINDINGS
    # ==========================================================================
    with tab_findings:
        st.subheader("Confirmed Vulnerability Findings")
        if not findings:
            st.success("✅ **Zero Vulnerability Findings Detected**")
            st.write("All monitored business-logic invariants held securely during testing.")
        else:
            for idx, f in enumerate(findings, 1):
                fid = f.get("id")
                scen_id = f.get("scenario_id")
                title = f.get("title")
                severity = f.get("severity", "HIGH")
                desc = f.get("description", "")
                impact = f.get("impact", "")
                remediation = f.get("remediation", "")
                evidence_refs = f.get("evidence_references", [])

                badge = get_severity_badge(severity)

                with st.container(border=True):
                    col_t1, col_t2 = st.columns([3, 1])
                    with col_t1:
                        st.markdown(f"### #{idx}. {title}")
                        st.caption(f"Finding ID: `{fid}` | Scenario: `{scen_id}`")
                    with col_t2:
                        st.markdown(f"<div style='text-align:right;'>{badge}</div>", unsafe_allow_html=True)

                    st.markdown(f"**Description:**\n{desc}")
                    st.markdown(f"**Business Impact:**\n{impact}")
                    st.markdown(f"**Remediation Guidance:**\n{remediation}")

                    if evidence_refs:
                        st.markdown("**Evidence Trail References:**")
                        for ref in evidence_refs:
                            st.code(ref, language="text")

    # ==========================================================================
    # TAB 4: EVIDENCE INSPECTOR
    # ==========================================================================
    with tab_evidence:
        st.subheader("Sanitized Forensic Evidence Inspector")
        st.caption("Inspect raw, sanitized HTTP requests and responses. All passwords, session tokens, and admin keys are masked.")

        scen_options = [s.get("scenario_id") for s in scenario_results]
        if scen_options:
            selected_scen_id = st.selectbox("Select Scenario Evidence to Inspect:", scen_options)
            chosen_scen = next((s for s in scenario_results if s.get("scenario_id") == selected_scen_id), None)

            if chosen_scen and chosen_scen.get("evidence"):
                evidence_list = chosen_scen.get("evidence", [])
                st.info(f"Showing **{len(evidence_list)}** recorded forensic steps for `{selected_scen_id}`:")

                for step_idx, ev in enumerate(evidence_list, 1):
                    endpoint = ev.get("endpoint", "")
                    obs = ev.get("observed_state") or {}
                    step_name = obs.get("step") if isinstance(obs, dict) else f"Step {step_idx}"
                    req = ev.get("request_summary") or {}
                    resp = ev.get("response_summary") or {}

                    with st.expander(f"Step {step_idx}: {step_name} [{req.get('method', 'GET')} {endpoint}]"):
                        col_req, col_resp = st.columns(2)
                        with col_req:
                            st.markdown("**Request Details (Sanitized):**")
                            st.write(f"• **Method:** `{req.get('method')}`")
                            st.write(f"• **Endpoint:** `{req.get('endpoint')}`")
                            st.markdown("**Headers:**")
                            st.json(req.get("headers") or {})
                            st.markdown("**Payload:**")
                            st.json(req.get("payload") or {})

                        with col_resp:
                            st.markdown("**Response Details (Sanitized):**")
                            st.write(f"• **Status Code:** `{resp.get('status_code')}`")
                            if resp.get("error"):
                                st.write(f"• **Error:** `{resp.get('error')}`")
                            st.markdown("**Response Body:**")
                            st.json(resp.get("payload") or {})
            else:
                st.write("No granular step evidence recorded for this scenario.")

    # ==========================================================================
    # TAB 5: ASSESSMENT HISTORY
    # ==========================================================================
    with tab_history:
        st.subheader("Historical Assessment Records")
        st.caption("All assessment records are saved locally as sanitized JSON files in instance/flowguard_history/.")

        history_items = history_store.list_assessments()
        if not history_items:
            st.info("No prior assessments found in history.")
        else:
            for item in history_items:
                with st.container(border=True):
                    c_info, c_action, c_pdf = st.columns([3.4, 0.9, 0.9])
                    with c_info:
                        st.markdown(f"**Assessment `{item['assessment_id']}`** — Target Mode: `{item['mode'].upper()}`")
                        st.write(
                            f"PNRI Score: **{item['pnri_score']:.1f}%** ({item['risk_band']}) | "
                            f"Findings: **{item['findings_count']}** | "
                            f"Completeness: **{item.get('completeness_pct', 100):.1f}%** | "
                            f"Executed: `{item['start_time'][:19]}`"
                        )
                    with c_action:
                        if st.button("📂 Load View", key=f"hist_load_{item['assessment_id']}"):
                            loaded_data = history_store.load_assessment(item["assessment_id"])
                            if loaded_data:
                                st.session_state.current_summary = loaded_data
                                st.rerun()
                    with c_pdf:
                        hist_data = history_store.load_assessment(item["assessment_id"])
                        if hist_data:
                            try:
                                hist_pdf_bytes = generate_pdf_report(hist_data)
                                st.download_button(
                                    label="📄 PDF",
                                    data=hist_pdf_bytes,
                                    file_name=f"FLOWGUARD_Report_{item['assessment_id']}.pdf",
                                    mime="application/pdf",
                                    key=f"hist_pdf_{item['assessment_id']}",
                                )
                            except Exception as exc:
                                st.caption(f"Error: {exc}")


if __name__ == "__main__":
    main()
