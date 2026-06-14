"""AEGIS Dashboard — Merged Flask + Socket.IO Backend.

Combines Adil's real-time backend with the user's Aegis visual design.
Reads detection_logs.json and deception_logs.json, pushes via Socket.IO.
Supports both JSON array and JSONL (one JSON object per line) formats.
"""
import os, json, time, threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from config import (
    DATA_DIR, DETECTION_LOG_FILE, DECEPTION_LOG_FILE,
    DASHBOARD_REFRESH_MS, MODELS_DIR
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "aegis-ids-2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ── Ensure data directory exists ──────────────────────────────────
os.makedirs(DATA_DIR, exist_ok=True)


# ── JSON / JSONL loader ───────────────────────────────────────────
def load_json(path):
    """Load a log file. Handles both JSON array and JSONL formats."""
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, "r") as f:
        content = f.read().strip()
    if not content:
        return []
    # Try JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        pass
    # Fall back to JSONL (one JSON object per line)
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def append_to_jsonl(path, entry):
    """Append a single JSON object as a new line (JSONL format)."""
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Stats computation ─────────────────────────────────────────────
def compute_stats(logs):
    total = len(logs)
    attacks = sum(1 for e in logs if e.get("label") == 1 or e.get("prediction") == 1)
    benign = total - attacks
    blocked = sum(1 for e in logs if e.get("action") == "BLOCK")
    return {
        "total_events": total,
        "attacks": attacks,
        "benign": benign,
        "blocked": blocked,
        "attack_rate": round(attacks / total * 100, 1) if total else 0
    }


def compute_deception_stats(logs):
    redirects = sum(1 for e in logs if e.get("event_type") == "REDIRECT")
    blacklists = sum(1 for e in logs if e.get("event_type") == "BLACKLIST")
    mutations = sum(1 for e in logs if e.get("event_type") in ("MUTATE", "ROTATE_DONE"))
    return {
        "total_events": len(logs),
        "redirects": redirects,
        "blacklists": blacklists,
        "mutations": mutations
    }


def get_threat_level(deception_logs):
    recent = [
        e for e in deception_logs
        if (datetime.now() - datetime.fromisoformat(e["timestamp"])).seconds < 300
    ] if deception_logs else []
    redir = sum(1 for e in recent if e.get("event_type") == "REDIRECT")
    bl = sum(1 for e in recent if e.get("event_type") == "BLACKLIST")
    if bl > 0:
        return "CRITICAL"
    if redir > 5:
        return "HIGH"
    if redir > 2:
        return "MEDIUM"
    return "LOW"


# ── Routes ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    det_logs = load_json(DETECTION_LOG_FILE)
    dec_logs = load_json(DECEPTION_LOG_FILE)
    return {
        "detection": compute_stats(det_logs),
        "deception": compute_deception_stats(dec_logs),
        "threat_level": get_threat_level(dec_logs)
    }


@app.route("/api/events")
def api_events():
    det_logs = load_json(DETECTION_LOG_FILE)
    dec_logs = load_json(DECEPTION_LOG_FILE)
    all_events = []
    for e in det_logs[-50:]:
        all_events.append({
            "timestamp": e.get("timestamp", ""),
            "type": "detection",
            "src_ip": e.get("src_ip", "?"),
            "dst_port": e.get("dst_port", "?"),
            "prediction": e.get("prediction", 0),
            "label": e.get("label", 0)
        })
    for e in dec_logs[-50:]:
        all_events.append({
            "timestamp": e.get("timestamp", ""),
            "type": "deception",
            "event_type": e.get("event_type", "?"),
            "src_ip": e.get("src_ip", ""),
            "details": {k: v for k, v in e.items() if k not in ("timestamp", "event_type")}
        })
    all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return all_events[:100]


# ── POST endpoints (bridge + deception → dashboard) ────────────────
@app.route("/api/alert", methods=["POST"])
def api_alert():
    """Receive alert from bridge, persist, and push to clients."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "no json"}), 400

    entry = {
        "timestamp": data.get("timestamp", datetime.now().isoformat()),
        "src_ip": data.get("src_ip", "unknown"),
        "dst_port": data.get("dst_port", 0),
        "prediction": 1,
        "confidence": data.get("confidence", 0),
        "scan_type": data.get("scan_type", "unknown"),
        "action": data.get("action", "ALERT"),
        "label": 1
    }
    append_to_jsonl(DETECTION_LOG_FILE, entry)

    # Push to connected clients immediately
    socketio.emit("new_event", {"type": "detection", "data": entry})
    return jsonify({"ok": True}), 201


@app.route("/api/block", methods=["POST"])
def api_block():
    """Receive block request from bridge, apply firewall rule, persist."""
    data = request.get_json(force=True, silent=True)
    if not data or "ip" not in data:
        return jsonify({"error": "missing ip"}), 400

    src_ip = data["ip"]

    # Apply firewall block (best-effort, requires root)
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'deception'))
        from monitor_interface import block_ip
        block_ip(src_ip)
    except Exception as e:
        print(f"[DASHBOARD] block_ip failed (need root?): {e}")

    entry = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "action": "BLOCK",
        "prediction": 1,
        "confidence": data.get("confidence", 1.0),
        "label": 1
    }
    append_to_jsonl(DETECTION_LOG_FILE, entry)

    socketio.emit("new_event", {"type": "detection", "data": entry})
    return jsonify({"ok": True}), 201


@app.route("/api/honeypot_event", methods=["POST"])
def api_honeypot_event():
    """Receive deception event from honeypot/MTD modules, persist, and push."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "no json"}), 400

    entry = {
        "timestamp": data.get("timestamp", datetime.now().isoformat()),
        "event_type": data.get("service", data.get("event_type", "UNKNOWN")),
        "src_ip": data.get("src_ip", "unknown"),
        "details": data.get("commands", data.get("details", "")),
    }
    append_to_jsonl(DECEPTION_LOG_FILE, entry)

    socketio.emit("new_event", {"type": "deception", "data": entry})
    return jsonify({"ok": True}), 201


# ── Background push ───────────────────────────────────────────────
def background_push():
    """Push live data to connected clients every REFRESH_MS."""
    while True:
        det_logs = load_json(DETECTION_LOG_FILE)
        dec_logs = load_json(DECEPTION_LOG_FILE)
        socketio.emit("stats_update", {
            "detection": compute_stats(det_logs),
            "deception": compute_deception_stats(dec_logs),
            "threat_level": get_threat_level(dec_logs)
        })
        recent_det = det_logs[-20:] if det_logs else []
        recent_dec = dec_logs[-20:] if dec_logs else []
        socketio.emit("events_update", {
            "detection": recent_det,
            "deception": recent_dec
        })
        time.sleep(DASHBOARD_REFRESH_MS / 1000)


@socketio.on("connect")
def on_connect():
    det_logs = load_json(DETECTION_LOG_FILE)
    dec_logs = load_json(DECEPTION_LOG_FILE)
    socketio.emit("stats_update", {
        "detection": compute_stats(det_logs),
        "deception": compute_deception_stats(dec_logs),
        "threat_level": get_threat_level(dec_logs)
    })


if __name__ == "__main__":
    t = threading.Thread(target=background_push, daemon=True)
    t.start()
    print("[AEGIS] Dashboard running on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
