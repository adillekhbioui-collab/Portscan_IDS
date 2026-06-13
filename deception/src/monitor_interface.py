"""Deception Monitor — Real-time dashboard for the deception subsystem.

Displays deception port activity, attacker tracking, threat levels
and MTD rotation status from the shared JSON log.
"""
import sys, os, json, time, datetime, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import DECEPTION_LOG_FILE, REFRESH_MS

INTERFACE = "deception-ids"

def calculate_threat_level(logs):
    """Score the current threat level from recent deception events."""
    recent = [
        e for e in logs
        if (datetime.datetime.now() - datetime.datetime.fromisoformat(e["timestamp"])).seconds < 300
    ]
    redirects = sum(1 for e in recent if e["event_type"] == "REDIRECT")
    blacklists = sum(1 for e in recent if e["event_type"] == "BLACKLIST")
    if blacklists > 0:
        return "CRITICAL"
    if redirects > 5:
        return "HIGH"
    if redirects > 2:
        return "MEDIUM"
    return "LOW"

def display_dashboard():
    """Print a simple terminal dashboard of deception telemetry."""
    try:
        with open(DECEPTION_LOG_FILE, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    threat = calculate_threat_level(logs)
    recent = logs[-10:] if logs else []
    os.system("clear" if os.name == "posix" else "cls")

    print(f" [SYSTEM] NODE: ENSA-01|INTERFACE: {INTERFACE}|TIME: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f" [THREAT] Level: {threat}")
    print(f" [EVENTS] Total: {len(logs)}")
    print()
    print(f" {'Timestamp':<26} {'Event':<20} {'Details'}")
    print(" " + "-" * 72)
    for ev in recent:
        ts = ev.get("timestamp", "?")[:19]
        et = ev.get("event_type", "?")
        detail_keys = {k: v for k, v in ev.items() if k not in ("timestamp", "event_type")}
        print(f" {ts:<26} {et:<20} {detail_keys}")
    print()
    print(f" Press Ctrl+C to stop | Refresh every {REFRESH_MS // 1000}s")


if __name__ == "__main__":
    try:
        while True:
            display_dashboard()
            time.sleep(REFRESH_MS / 1000)
    except KeyboardInterrupt:
        print("\n[*] Terminating deception monitor.")
