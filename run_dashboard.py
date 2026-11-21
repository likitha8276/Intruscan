"""One-click launcher for the INTRUSCAN SOC Dashboard."""

import os
import subprocess
import sys
import webbrowser
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def main():
    print("=" * 60)
    print("🛡️  Starting INTRUSCAN SOC Dashboard")
    print("=" * 60)

    # Ensure demo dataset is initialized
    demo_db = ROOT / "demo_data" / "incidents.db"
    demo_flows = ROOT / "demo_data" / "scored_flows.jsonl"
    if not demo_db.is_file() or not demo_flows.is_file():
        print("Initializing realistic demonstration datasets...")
        from tools.generate_demo_dataset import generate_demo_incidents, generate_demo_flows
        generate_demo_incidents()
        generate_demo_flows()
        print("Demo data initialized successfully.")

    dashboard_app = ROOT / "dashboard" / "app.py"

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dashboard_app),
        "--browser.gatherUsageStats=false",
    ]

    print("\n🌐 Opening INTRUSCAN SOC Dashboard in your browser at:")
    print("   👉 http://localhost:8501")
    print("   (Press Ctrl+C to stop the server)\n")

    try:
        subprocess.run(cmd, cwd=ROOT)
    except KeyboardInterrupt:
        print("\n🛡️  INTRUSCAN SOC Dashboard stopped cleanly.")

if __name__ == "__main__":
    main()
