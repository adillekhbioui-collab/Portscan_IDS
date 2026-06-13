"""Core Deception Engine — Portscan_IDS / Aegis Entropy integration.

Provides dynamic honeypot surface generation, attacker tracking, phantom
network deployment and automatic blackholing for detected scanners.
"""
import sys, os, asyncio, json, datetime, subprocess, random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    DECEPTION_LOG_FILE, DECEPTION_PORT_START, DECEPTION_PORT_END,
    BAN_THRESHOLD, DECEPTION_INTERFACE
)

THREAT_LOG = DECEPTION_LOG_FILE

os.makedirs(os.path.dirname(THREAT_LOG), exist_ok=True)

def log_event(event_type, details):
    """Append a structured event to the deception log."""
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        **details
    }
    try:
        with open(THREAT_LOG, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    logs.append(entry)
    with open(THREAT_LOG, "w") as f:
        json.dump(logs, f, indent=2)
    return entry


async def handle_attacker(src_ip, dst_port):
    """Route an attacker to a deception port via iptables REDIRECT."""
    decoy_port = random.randint(DECEPTION_PORT_START, DECEPTION_PORT_END)
    try:
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", DECEPTION_INTERFACE, "-s", src_ip,
             "-p", "tcp", "--dport", str(dst_port),
             "-j", "REDIRECT", "--to-port", str(decoy_port)],
            check=True, timeout=5
        )
        log_event("REDIRECT", {
            "src_ip": src_ip,
            "original_port": dst_port,
            "decoy_port": decoy_port
        })
        return True
    except subprocess.SubprocessError as e:
        log_event("REDIRECT_FAILED", {"src_ip": src_ip, "error": str(e)})
        return False


async def deploy_phantom_network(subnet="10.0.200.0/24"):
    """Create phantom IPs via local ARP replies to confuse OSINT."""
    try:
        subprocess.run(
            ["ip", "addr", "add", f"{subnet}".replace("/24", "/24"),
             "dev", DECEPTION_INTERFACE],
            check=True, timeout=5
        )
        log_event("PHANTOM_DEPLOY", {"subnet": subnet})
        return True
    except subprocess.SubprocessError as e:
        log_event("PHANTOM_FAILED", {"subnet": subnet, "error": str(e)})
        return False


async def blacklist_ip(src_ip):
    """Add an IP to the DROP chain after exceeding BAN_THRESHOLD."""
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", src_ip,
             "-j", "DROP"],
            check=True, timeout=5
        )
        log_event("BLACKLIST", {"src_ip": src_ip})
        return True
    except subprocess.SubprocessError as e:
        log_event("BLACKLIST_FAILED", {"src_ip": src_ip, "error": str(e)})
        return False


if __name__ == "__main__":
    PORT_RANGE = range(DECEPTION_PORT_START, DECEPTION_PORT_END + 1)
    asyncio.run(deploy_phantom_network())
