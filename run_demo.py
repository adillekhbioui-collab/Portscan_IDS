#!/usr/bin/env python3
"""
AEGIS Entropy — Unified Demo Entry Point
==========================================
Starts the dashboard and runs the detection pipeline.

Usage:
    python run_demo.py                    # Interactive menu
    python run_demo.py --offline          # Skip menu, run offline demo
    python run_demo.py --dashboard-only   # Start dashboard only
"""
import os
import sys
import time
import threading
import subprocess
import argparse

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import config


def ensure_dirs():
    """Ensure runtime directories exist."""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.MODELS_DIR, exist_ok=True)


def start_dashboard():
    """Start the Flask dashboard in a background thread."""
    print("[AEGIS] Starting dashboard...")
    from dashboard.app import app, socketio, background_push

    t = threading.Thread(target=background_push, daemon=True)
    t.start()

    server = threading.Thread(
        target=lambda: socketio.run(
            app, host="0.0.0.0", port=config.DASHBOARD_PORT,
            debug=False, allow_unsafe_werkzeug=True
        ),
        daemon=True,
    )
    server.start()
    time.sleep(2)  # Let Flask bind
    print(f"[AEGIS] Dashboard running at http://localhost:{config.DASHBOARD_PORT}")
    return server


def run_offline_demo():
    """Run the offline Nmap → ML → Dashboard pipeline."""
    print("\n" + "=" * 60)
    print("  AEGIS Entropy — Offline Demo")
    print("=" * 60)

    scans_dir = os.path.join(PROJECT_ROOT, "capture", "scans")
    csv_output = os.path.join(PROJECT_ROOT, "nmap_features.csv")

    # Step 1: Parse Nmap XMLs
    print("\n[1/3] Parsing Nmap scan files...")
    nmap_parser = os.path.join(PROJECT_ROOT, "bridge", "nmap_parser.py")
    if not os.path.exists(nmap_parser):
        print(f"[ERROR] nmap_parser.py not found at {nmap_parser}")
        return

    result = subprocess.run(
        [sys.executable, nmap_parser, "--scans-dir", scans_dir, "--output", csv_output],
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print("[ERROR] Nmap parsing failed.")
        return

    if not os.path.exists(csv_output):
        print("[ERROR] CSV output not created.")
        return

    # Step 2: Run ML prediction via bridge
    print("\n[2/3] Running ML prediction...")
    bridge_script = os.path.join(PROJECT_ROOT, "bridge", "bridge.py")
    result = subprocess.run(
        [sys.executable, bridge_script, "--input", csv_output],
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print("[WARNING] Bridge encountered errors (check output above).")

    # Step 3: Summary
    print("\n[3/3] Checking results...")
    det_log = config.DETECTION_LOG_FILE
    if os.path.exists(det_log):
        with open(det_log, "r") as f:
            lines = f.readlines()
        alerts = sum(1 for l in lines if '"prediction": 1' in l or '"prediction":1' in l)
        print(f"\n[DONE] {len(lines)} events logged, {alerts} attacks detected.")
    else:
        print(f"\n[DONE] No log file found at {det_log}")

    print(f"\n  Dashboard:  http://localhost:{config.DASHBOARD_PORT}")
    print("  Press Ctrl+C to stop.\n")

    # Keep alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[AEGIS] Shutting down.")


def run_live_demo():
    """Start the live capture bridge (requires Scapy + root)."""
    print("\n" + "=" * 60)
    print("  AEGIS Entropy — Live Capture Mode")
    print("=" * 60)
    print("[INFO] Live mode requires root privileges and a valid interface.")
    print(f"[INFO] Interface: {config.IDS_INTERFACE}")
    print("[INFO] Press Ctrl+C to stop.\n")

    bridge_script = os.path.join(PROJECT_ROOT, "bridge", "bridge.py")
    try:
        subprocess.run(
            [sys.executable, bridge_script, "--input", "live"],
            cwd=PROJECT_ROOT,
        )
    except KeyboardInterrupt:
        print("\n[AEGIS] Stopping live capture.")


def interactive_menu():
    """Show the mode selection menu."""
    print("\n" + "=" * 60)
    print("  AEGIS Entropy — Adaptive Entropy-based Gateway")
    print("  for Intrusion Suppression")
    print("=" * 60)
    print()
    print("  Select demo mode:")
    print()
    print("    [1] Offline Demo  — Parse saved Nmap scans → ML → Dashboard")
    print("    [2] Live Capture  — Real-time Scapy capture → ML → Dashboard")
    print("    [3] Dashboard Only — Start dashboard, no pipeline")
    print("    [q] Quit")
    print()

    while True:
        choice = input("  Enter choice (1/2/3/q): ").strip().lower()
        if choice == "1":
            return "offline"
        elif choice == "2":
            return "live"
        elif choice == "3":
            return "dashboard"
        elif choice == "q":
            return "quit"
        else:
            print("  Invalid choice. Try again.")


def main():
    parser = argparse.ArgumentParser(description="AEGIS Entropy — Unified Demo")
    parser.add_argument("--offline", action="store_true", help="Run offline demo directly")
    parser.add_argument("--live", action="store_true", help="Run live capture directly")
    parser.add_argument("--dashboard-only", action="store_true", help="Start dashboard only")
    args = parser.parse_args()

    ensure_dirs()

    # Determine mode
    if args.offline:
        mode = "offline"
    elif args.live:
        mode = "live"
    elif args.dashboard_only:
        mode = "dashboard"
    else:
        mode = interactive_menu()

    if mode == "quit":
        print("[AEGIS] Goodbye.")
        return

    # Start dashboard
    start_dashboard()

    # Run selected mode
    if mode == "offline":
        run_offline_demo()
    elif mode == "live":
        run_live_demo()
    elif mode == "dashboard":
        print(f"\n[AEGIS] Dashboard running at http://localhost:{config.DASHBOARD_PORT}")
        print("        Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[AEGIS] Shutting down.")


if __name__ == "__main__":
    main()
