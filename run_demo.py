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
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import config


def ensure_dirs():
    """Ensure runtime directories exist."""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.MODELS_DIR, exist_ok=True)


def check_models():
    """Verify that the trained model artifacts exist before starting the demo."""
    required = {
        "Random Forest model": config.RF_MODEL_PATH,
        "StandardScaler": config.SCALER_PATH,
    }
    missing = [name for name, path in required.items() if not os.path.exists(path)]
    if missing:
        print("\n[ERROR] Missing required model files:")
        for name in missing:
            print(f"  - {name}: {required[name]}")
        print("\nPlease train the models first or place the .pkl files in:")
        print(f"  {config.MODELS_DIR}")
        sys.exit(1)


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

    # Wait for Flask to actually accept connections (up to 10 seconds)
    url = f"http://localhost:{config.DASHBOARD_PORT}/api/stats"
    for i in range(20):
        try:
            urllib.request.urlopen(url, timeout=0.5)
            print(f"[AEGIS] Dashboard ready at http://localhost:{config.DASHBOARD_PORT}")
            return server
        except Exception:
            time.sleep(0.5)

    print(f"[WARNING] Dashboard did not become ready at {url} — continuing anyway.")
    print(f"[AEGIS] Dashboard should be available at http://localhost:{config.DASHBOARD_PORT}")
    return server


def run_offline_demo():
    """Run the offline Nmap → ML → Dashboard pipeline with demo attack traffic."""
    print("\n" + "=" * 60)
    print("  AEGIS Entropy — Offline Demo")
    print("=" * 60)

    # Start with a fresh detection log so each demo run shows reproducible numbers
    det_log = config.DETECTION_LOG_FILE
    if os.path.exists(det_log):
        try:
            os.remove(det_log)
            print(f"[AEGIS] Cleared previous detection log: {det_log}")
        except Exception as e:
            print(f"[WARNING] Could not clear detection log: {e}")

    scans_dir = os.path.join(PROJECT_ROOT, "capture", "scans")
    nmap_csv = os.path.join(PROJECT_ROOT, "nmap_features.csv")
    attack_csv = os.path.join(PROJECT_ROOT, "demo", "demo_attack.csv")
    bridge_script = os.path.join(PROJECT_ROOT, "bridge", "bridge.py")

    if not os.path.isdir(scans_dir):
        print(f"[ERROR] Scan directory not found: {scans_dir}")
        return

    # Step 1: Parse Nmap XMLs (benign background traffic)
    print("\n[1/4] Parsing Nmap scan files...")
    nmap_parser = os.path.join(PROJECT_ROOT, "bridge", "nmap_parser.py")
    if not os.path.exists(nmap_parser):
        print(f"[ERROR] nmap_parser.py not found at {nmap_parser}")
        return

    result = subprocess.run(
        [sys.executable, nmap_parser, "--scans-dir", scans_dir, "--output", nmap_csv],
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print("[ERROR] Nmap parsing failed.")
        return

    if not os.path.exists(nmap_csv):
        print("[ERROR] CSV output not created.")
        return

    # Step 2: Combine Nmap features + demo attack traffic
    print("\n[2/4] Combining benign Nmap traffic with demo attack traffic...")
    combined_csv = os.path.join(PROJECT_ROOT, "demo_features.csv")
    if not os.path.exists(attack_csv):
        print(f"[WARNING] Demo attack CSV not found at {attack_csv} — using Nmap traffic only.")
        combined_csv = nmap_csv
    else:
        with open(combined_csv, "w", newline="") as out_f:
            # Copy Nmap CSV
            with open(nmap_csv, "r") as f:
                out_f.write(f.read())
            # Append attack CSV without header
            with open(attack_csv, "r") as f:
                lines = f.readlines()
                if len(lines) > 1:
                    out_f.writelines(lines[1:])
        print(f"  Combined {os.path.getsize(nmap_csv)} bytes + {os.path.getsize(attack_csv)} bytes")

    # Step 3: Run ML prediction once (loads model once, faster)
    print("\n[3/4] Running ML prediction...")
    result = subprocess.run(
        [sys.executable, bridge_script, "--input", combined_csv],
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print("[WARNING] Bridge encountered errors.")

    # Step 4: Summary
    print("\n[4/4] Checking results...")
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


def interactive_menu():
    """Show the mode selection menu."""
    print("\n" + "=" * 60)
    print("  AEGIS Entropy — Adaptive Entropy-based Gateway")
    print("  for Intrusion Suppression")
    print("=" * 60)
    print()
    print("  Select demo mode:")
    print()
    print("    [1] Offline Demo   — Parse saved Nmap scans → ML → Dashboard")
    print("    [2] Dashboard Only — Start dashboard, no pipeline")
    print("    [q] Quit")
    print()

    while True:
        choice = input("  Enter choice (1/2/q): ").strip().lower()
        if choice == "1":
            return "offline"
        elif choice == "2":
            return "dashboard"
        elif choice == "q":
            return "quit"
        else:
            print("  Invalid choice. Try again.")


def main():
    parser = argparse.ArgumentParser(description="AEGIS Entropy — Unified Demo")
    parser.add_argument("--offline", action="store_true", help="Run offline demo directly")
    parser.add_argument("--dashboard-only", action="store_true", help="Start dashboard only")
    args = parser.parse_args()

    ensure_dirs()
    check_models()

    # Determine mode
    if args.offline:
        mode = "offline"
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
