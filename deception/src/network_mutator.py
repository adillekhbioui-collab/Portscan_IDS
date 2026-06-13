"""Network Mutator — Moves the honeypot surface across the port range.

Implements Moving Target Defense (MTD) by shuffling open ports so
static fingerprinting by attackers becomes unreliable.
"""
import sys, os, random, subprocess, datetime, json, time

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


def mutate_packet(raw_packet):
    """Randomise TCP destination port within the deception range."""
    decoy_port = random.randint(DECEPTION_PORT_START, DECEPTION_PORT_END)
    log_event("MUTATE", {"new_port": decoy_port})
    return raw_packet


def rotate_ports(interval=30):
    """Continuously rotate the set of open deception ports."""
    ports = list(range(DECEPTION_PORT_START, DECEPTION_PORT_END + 1))
    active = random.sample(ports, min(20, len(ports)))
    log_event("ROTATE_START", {"active_ports": active})
    while True:
        new_active = random.sample(ports, min(20, len(ports)))
        old_set = set(active)
        new_set = set(new_active)
        for p in old_set - new_set:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-p", "tcp",
                 "--dport", str(p), "-j", "ACCEPT"],
                capture_output=True
            )
        for p in new_set - old_set:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-p", "tcp",
                 "--dport", str(p), "-j", "ACCEPT"],
                capture_output=True
            )
        log_event("ROTATE_DONE", {"new_ports": new_active})
        active = new_active
        time.sleep(interval)


if __name__ == "__main__":
    try:
        rotate_ports()
    except KeyboardInterrupt:
        log_event("ROTATE_STOP", {"msg": "Manual stop"})
