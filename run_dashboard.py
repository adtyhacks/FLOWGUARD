#!/usr/bin/env python3
"""Launcher for the FLOWGUARD Streamlit Dashboard.

Usage:
  python run_dashboard.py
  streamlit run run_dashboard.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass


def main() -> None:
    # If run directly via streamlit ("streamlit run run_dashboard.py")
    if os.getenv("STREAMLIT_RUN", "").lower() == "true" or "streamlit" in sys.argv[0]:
        from dashboard.app import main as app_main
        app_main()
        return

    # If run via python ("python run_dashboard.py")
    import subprocess

    app_path = Path(__file__).resolve().parent / "dashboard" / "app.py"
    port = os.getenv("FLOWGUARD_DASHBOARD_PORT", "8501")
    host = os.getenv("FLOWGUARD_DASHBOARD_HOST", "127.0.0.1")

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        f"--server.port={port}",
        f"--server.address={host}",
        "--browser.serverAddress=localhost",
    ]

    print("=" * 64)
    print("   FLOWGUARD — Starting Streamlit Visual Dashboard")
    print("=" * 64)
    print(f"[*] Dashboard URL: http://{host}:{port}")
    print(f"[*] App Path     : {app_path}")
    print("[*] Press Ctrl+C to stop.")
    print("-" * 64)

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")


if __name__ == "__main__":
    main()
