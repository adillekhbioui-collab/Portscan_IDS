# ============================================
# Pôle 4 — Adil
# AEGIS Dashboard: Flask + Socket.IO Backend
# ============================================

import os
import sys
import json
import time
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# Add project root to path for config import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

# ── Flask App ──────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "aegis-dashboard-secret"
socketio = SocketIO(app, cors_allowed_origins="*")

# ── In-Memory State ───────────────────────────────
# These get updated by the detection pipeline and pushed to the browser
state = {
    "alerts": [],              # List of detection alerts
    "active_scanners": {},     # {ip: {scan_type, confidence, first_seen, last_seen, ports_count}}
    "attacker_profiles": {},   # {ip: {detailed profile with honeypot info}}
    "blocked_ips": [],         # List of blocked IPs
    "honeypot_events": [],     # Honeypot interaction log
    "mtd_events": [],          # MTD rotation log
    "stats": {                 # Summary counters
        "total_alerts": 0,
        "active_threats": 0,
        "blocked_count": 0,
        "honeypot_hits": 0,
    }
}


# ── Routes ─────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/api/state")
def get_state():
    """Return current system state as JSON (for initial page load)."""
    return jsonify(state)


@app.route("/api/alert", methods=["POST"])
def receive_alert():
    """
    Receive a detection alert from the capture/ML pipeline.
    
    Expected JSON body:
    {
        "src_ip": "192.168.1.105",
        "prediction": "PORT_SCAN",
        "confidence": 0.92,
        "scan_type": "SYN",
        "features": [12-element list],
        "honeypot_flag": 0 or 1,
        "timestamp": "2026-04-28T21:30:00"
    }
    """
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    src_ip = data.get("src_ip", "unknown")
    confidence = data.get("confidence", 0.0)
    scan_type = data.get("scan_type", "UNKNOWN")
    honeypot_flag = data.get("honeypot_flag", 0)
    timestamp = data.get("timestamp", datetime.now().isoformat())

    # Build alert object
    alert = {
        "id": len(state["alerts"]) + 1,
        "src_ip": src_ip,
        "prediction": data.get("prediction", "PORT_SCAN"),
        "confidence": round(confidence, 3),
        "scan_type": scan_type,
        "honeypot_flag": honeypot_flag,
        "timestamp": timestamp,
        "severity": _compute_severity(confidence, honeypot_flag),
    }

    # Update state
    state["alerts"].insert(0, alert)  # newest first
    state["alerts"] = state["alerts"][:100]  # keep last 100
    state["stats"]["total_alerts"] += 1

    # Update active scanners
    if src_ip not in state["active_scanners"]:
        state["active_scanners"][src_ip] = {
            "scan_type": scan_type,
            "confidence": confidence,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "alert_count": 1,
            "honeypot_hit": honeypot_flag == 1,
        }
    else:
        scanner = state["active_scanners"][src_ip]
        scanner["last_seen"] = timestamp
        scanner["alert_count"] += 1
        scanner["confidence"] = max(scanner["confidence"], confidence)
        if honeypot_flag == 1:
            scanner["honeypot_hit"] = True

    state["stats"]["active_threats"] = len(state["active_scanners"])

    # Push to all connected browsers via Socket.IO
    socketio.emit("new_alert", alert)
    socketio.emit("state_update", {
        "stats": state["stats"],
        "active_scanners": state["active_scanners"],
    })

    return jsonify({"status": "ok", "alert_id": alert["id"]})


@app.route("/api/honeypot_event", methods=["POST"])
def receive_honeypot_event():
    """
    Receive honeypot interaction event from El Yazid's honeypot parser.
    
    Expected JSON body:
    {
        "src_ip": "192.168.1.105",
        "service": "SSH",
        "commands": ["cat /etc/passwd", "ls -la"],
        "credentials": ["root:admin", "root:123456"],
        "timestamp": "2026-04-28T21:35:00"
    }
    """
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    event = {
        "id": len(state["honeypot_events"]) + 1,
        "src_ip": data.get("src_ip", "unknown"),
        "service": data.get("service", "UNKNOWN"),
        "commands": data.get("commands", []),
        "credentials": data.get("credentials", []),
        "timestamp": data.get("timestamp", datetime.now().isoformat()),
    }

    state["honeypot_events"].insert(0, event)
    state["honeypot_events"] = state["honeypot_events"][:50]
    state["stats"]["honeypot_hits"] += 1

    # Update attacker profile with honeypot data
    src_ip = event["src_ip"]
    if src_ip not in state["attacker_profiles"]:
        state["attacker_profiles"][src_ip] = {
            "src_ip": src_ip,
            "honeypot_interactions": [],
        }
    state["attacker_profiles"][src_ip]["honeypot_interactions"].append(event)

    socketio.emit("honeypot_event", event)

    return jsonify({"status": "ok"})


@app.route("/api/block", methods=["POST"])
def block_attacker():
    """Manually trigger IP block from dashboard."""
    data = request.json
    ip = data.get("ip")
    if ip and ip not in state["blocked_ips"]:
        state["blocked_ips"].append(ip)
        state["stats"]["blocked_count"] = len(state["blocked_ips"])
        # TODO: Call response_engine.block_ip(ip) here
        socketio.emit("ip_blocked", {"ip": ip})
    return jsonify({"status": "ok"})


# ── Helpers ────────────────────────────────────────

def _compute_severity(confidence, honeypot_flag):
    """Compute alert severity based on confidence and honeypot interaction."""
    if honeypot_flag == 1:
        return "CRITICAL"
    elif confidence >= 0.90:
        return "HIGH"
    elif confidence >= 0.75:
        return "MEDIUM"
    else:
        return "LOW"


# ── Main ───────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  AEGIS Dashboard starting...")
    print(f"  http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print("=" * 50)
    socketio.run(
        app,
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=True,
        allow_unsafe_werkzeug=True,
    )
