#!/usr/bin/env python3
"""FLOWGUARD — Standalone Assessment Engine CLI.

Executes end-to-end security assessments against vulnerable or secure ShopZone targets,
evaluating all 7 core business logic scenarios, calculating the PNRI score, and
printing structured, sanitized audit results.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flowguard.config import FlowGuardConfig
from flowguard.runner import AssessmentRunner
from flowguard.schemas import AssessmentSummary, ScenarioResult


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="FLOWGUARD — E-Commerce Business Logic Security Assessment Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        required=True,
        help="Target ShopZone operating mode ('vulnerable' or 'secure').",
    )
    parser.add_argument(
        "--target-url",
        default=os.getenv("FLOWGUARD_BASE_URL", "http://127.0.0.1:5000"),
        help="Base URL of target ShopZone instance (default: http://127.0.0.1:5000).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("FLOWGUARD_TIMEOUT", "5.0")),
        help="Per-request HTTP timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--admin-key",
        default=os.getenv("ADMIN_KEY"),
        help="ShopZone X-Admin-Key for authoritative ground-truth verification.",
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="Run a specific scenario (e.g., TC-01) or 'all' (default: all).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the final assessment summary as sanitized JSON.",
    )

    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    return args


def print_banner(mode: str, target: str) -> None:
    """Print the assessment header banner."""
    print("=" * 76)
    print("   FLOWGUARD — Automated Business-Logic Security Assessment Engine")
    print("=" * 76)
    print(f" Target URL : {target}")
    print(f" Target Mode: {mode.upper()}")
    print("-" * 76)


def print_scenario_progress(scenario_id: str, result: ScenarioResult) -> None:
    """Format and print scenario outcome in real time."""
    status_tag = f"[{result.status}]"
    timing_tag = f"{result.duration_ms}ms"
    print(f" {scenario_id:<6} {status_tag:<14} {timing_tag:>8}  {result.actual_behavior}")
    if result.error:
        print(f"        └─ Details: {result.error}")


def print_assessment_report(summary: AssessmentSummary) -> None:
    """Format and print the final assessment report and PNRI score."""
    print("-" * 76)
    print(" ASSESSMENT FINDINGS & VULNERABILITY SUMMARY")
    print("-" * 76)

    if not summary.findings:
        print(" [+] No confirmed vulnerabilities detected.")
        if summary.mode == "secure":
            print("     All security invariants were successfully enforced by the secure target.")
    else:
        for idx, finding in enumerate(summary.findings, 1):
            print(f" #{idx} [{finding.severity}] {finding.id}: {finding.title}")
            print(f"    Impact     : {finding.impact}")
            print(f"    Remediation: {finding.remediation}")
            print()

    print("-" * 76)
    print(" METRICS & PNRI RISK INDEX")
    print("-" * 76)
    raw_score = summary.raw_risk_score
    pnri_score = summary.pnri_score
    risk_band = getattr(summary, "risk_band", "N/A")
    completeness = getattr(summary, "completeness_pct", 100.0)

    print(f" Raw Risk Score : {raw_score} / 125")
    print(f" PNRI Score     : {pnri_score:.2f} / 100.00 ({risk_band} Risk)")
    print(f" Completeness   : {completeness:.1f}%")
    print(f" Scenarios Total: {len(summary.scenario_results)}")
    print(f" Confirmed Flaws: {len(summary.findings)}")
    print("=" * 76)


def main(argv: list[str] | None = None) -> int:
    """Main entrypoint for CLI assessment execution."""
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return exc.code

    try:
        config = FlowGuardConfig(
            base_url=args.target_url,
            target_mode=args.mode,
            timeout=args.timeout,
            admin_key=args.admin_key,
        )
    except Exception as exc:
        print(f"[!] Configuration Error: {exc}", file=sys.stderr)
        return 2

    runner = AssessmentRunner(config, timeout=args.timeout)

    if not args.json:
        print_banner(args.mode, config.base_url)

    # Single scenario run
    if args.scenario.lower() != "all":
        scen_id = args.scenario.upper()
        try:
            result = runner.run_scenario(scen_id, mode=args.mode)
        except Exception as exc:
            print(f"[!] Error executing scenario {scen_id}: {exc}", file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print_scenario_progress(scen_id, result)
            print("-" * 76)
        return 0 if result.status in ("PASS", "FAIL") else 1

    # Full suite run
    progress_fn = None if args.json else print_scenario_progress
    try:
        summary = runner.run_all(mode=args.mode, progress_callback=progress_fn)
    except Exception as exc:
        print(f"[!] Unhandled assessment failure: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary.to_dict(), indent=2))
    else:
        print_assessment_report(summary)

    # Return 0 if assessment completed without transport/inconclusive errors
    inconclusive_count = getattr(summary, "inconclusive_count", 0)
    error_count = getattr(summary, "error_count", 0)

    if inconclusive_count > 0 or error_count > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
