"""Traffic Shaper — NetfilterQueue hook for real-time packet mutation.

Intercepts outgoing TCP via NFQUEUE and modifies destination ports
to funnel attackers toward the deception surface.
"""
import sys, os, json, datetime, subprocess
from netfilterqueue import NetfilterQueue

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    DECEPTION_LOG_FILE, DECEPTION_PORT_START, DECEPTION_PORT_END,
    DECEPTION_INTERFACE
)

THREAT_LOG = DECEPTION_LOG_FILE
os.makedirs(os.path.dirname(THREAT_LOG), exist_ok=True)

def log_event(event_type, details):
    entry = {"timestamp": datetime.datetime.now().isoformat(),
             "event_type": event_type, **details}
    try:
        with open(THREAT_LOG, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    logs.append(entry)
    with open(THREAT_LOG, "w") as f:
        json.dump(logs, f, indent=2)


def process_packet(pkt):
    """Mutate destination port on outgoing packets via NFQUEUE."""
    try:
        import random
        ip = pkt.get_ip()
        if ip and ip.dst:
            new_port = random.randint(DECEPTION_PORT_START, DECEPTION_PORT_END)
            pkt.set_param(pkt.NFQA_TCP_DST, new_port)
            log_event("TRAFFIC_SHAPE", {
                "original_dst": str(ip.dst),
                "new_port": new_port
            })
        pkt.accept()
    except Exception as e:
        log_event("SHAPE_ERROR", {"error": str(e)})
        pkt.accept()


def setup_nftables_queue():
    """Create NFQUEUE rule to intercept outgoing TCP traffic."""
    subprocess.run(
        ["iptables", "-A", "OUTPUT", "-p", "tcp",
         "-j", "NFQUEUE", "--queue-num", "1"],
        check=True, timeout=10
    )
    log_event("NFQUEUE_SETUP", {"queue_num": 1, "iface": DECEPTION_INTERFACE})


if __name__ == "__main__":
    setup_nftables_queue()
    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(1, process_packet)
        log_event("TRAFFIC_SHAPE_START", {"status": "listening"})
        nfqueue.run()
    except KeyboardInterrupt:
        log_event("TRAFFIC_SHAPE_STOP", {"msg": "Manual stop"})
    finally:
        nfqueue.unbind()
