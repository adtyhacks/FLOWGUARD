"""Plotly visualization components for the FLOWGUARD Streamlit dashboard."""

from __future__ import annotations

from typing import Any
import plotly.graph_objects as go


def create_pnri_gauge(pnri_score: float, risk_band: str) -> go.Figure:
    """Create a high-impact, professional radial gauge for the PNRI risk score."""
    # Determine needle/accent color based on band
    if pnri_score < 20.0:
        bar_color = "#28a745"  # Green
    elif pnri_score < 50.0:
        bar_color = "#ffc107"  # Yellow/Amber
    elif pnri_score < 75.0:
        bar_color = "#fd7e14"  # Orange
    else:
        bar_color = "#dc3545"  # Red

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=pnri_score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"<b>PNRI SCORE: {pnri_score:.1f}/100</b><br><span style='font-size:0.8em;color:{bar_color}'>{risk_band.upper()} RISK</span>", "font": {"size": 18}},
            number={"suffix": "%", "font": {"size": 32, "color": bar_color}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#888888"},
                "bar": {"color": bar_color, "thickness": 0.3},
                "bgcolor": "rgba(0,0,0,0.05)",
                "borderwidth": 1,
                "bordercolor": "#888888",
                "steps": [
                    {"range": [0, 20], "color": "rgba(40, 167, 69, 0.25)"},
                    {"range": [20, 50], "color": "rgba(255, 193, 7, 0.25)"},
                    {"range": [50, 75], "color": "rgba(253, 126, 20, 0.25)"},
                    {"range": [75, 100], "color": "rgba(220, 53, 69, 0.3)"},
                ],
                "threshold": {
                    "line": {"color": bar_color, "width": 4},
                    "thickness": 0.8,
                    "value": pnri_score,
                },
            },
        )
    )

    fig.update_layout(
        height=260,
        margin={"l": 20, "r": 20, "t": 40, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        font={"family": "sans-serif"},
    )
    return fig


def create_severity_breakdown_chart(findings: list[Any]) -> go.Figure:
    """Create a donut chart illustrating the distribution of confirmed findings by severity."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev = getattr(finding, "severity", None) if not isinstance(finding, dict) else finding.get("severity")
        if isinstance(sev, str) and sev.upper() in severity_counts:
            severity_counts[sev.upper()] += 1

    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    values = [severity_counts[k] for k in labels]
    colors = ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8"]

    if sum(values) == 0:
        # Empty placeholder state when no vulnerabilities are present (e.g. Secure mode)
        fig = go.Figure(
            go.Pie(
                labels=["No Confirmed Findings"],
                values=[1],
                hole=0.6,
                marker_colors=["#28a745"],
                textinfo="label",
                hoverinfo="none",
            )
        )
        fig.update_layout(
            title={"text": "<b>Findings Breakdown</b>", "font": {"size": 15}, "x": 0.5},
            height=260,
            margin={"l": 20, "r": 20, "t": 40, "b": 20},
            showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)",
        )
        return fig

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.55,
            marker_colors=colors,
            textinfo="value+percent",
            hoverinfo="label+value",
        )
    )
    fig.update_layout(
        title={"text": "<b>Findings by Severity</b>", "font": {"size": 15}, "x": 0.5},
        height=260,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        showlegend=True,
        legend={"orientation": "h", "yanchor": "bottom", "y": -0.2, "xanchor": "center", "x": 0.5},
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def create_scenario_status_chart(scenario_results: list[Any]) -> go.Figure:
    """Create a horizontal stacked bar summarizing scenario invariant outcomes."""
    status_counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0, "ERROR": 0}
    for res in scenario_results:
        st = getattr(res, "status", None) if not isinstance(res, dict) else res.get("status")
        if isinstance(st, str) and st.upper() in status_counts:
            status_counts[st.upper()] += 1

    fig = go.Figure()
    fig.add_trace(go.Bar(name="PASS (Secure)", x=[status_counts["PASS"]], y=["Scenarios"], orientation="h", marker_color="#28a745"))
    fig.add_trace(go.Bar(name="FAIL (Vulnerable)", x=[status_counts["FAIL"]], y=["Scenarios"], orientation="h", marker_color="#dc3545"))
    fig.add_trace(go.Bar(name="INCONCLUSIVE", x=[status_counts["INCONCLUSIVE"]], y=["Scenarios"], orientation="h", marker_color="#6c757d"))
    fig.add_trace(go.Bar(name="ERROR", x=[status_counts["ERROR"]], y=["Scenarios"], orientation="h", marker_color="#ffc107"))

    fig.update_layout(
        barmode="stack",
        height=140,
        margin={"l": 20, "r": 20, "t": 20, "b": 10},
        xaxis={"title": "Count (Total 7)", "range": [0, 7], "dtick": 1},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.05, "xanchor": "center", "x": 0.5},
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig
