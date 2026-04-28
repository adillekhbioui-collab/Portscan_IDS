# ============================================
# Pôle 4 — Adil  +  Pôle 2 — El Yazid
# Response Engine: iptables Blocking
# ============================================
# This script handles:
#   1. On confirmed detection (confidence >= 0.85):
#      → iptables -A INPUT -s <attacker_ip> -j DROP
#   2. TTL-based auto-unblock after config.AUTO_UNBLOCK_MINUTES
#   3. Audit log of all block/unblock actions
# ============================================

# TODO: Adil — implement this module
import subprocess
import config


def block_ip(ip_address):
    """Add iptables DROP rule for the given IP."""
    cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    # TODO: implement with subprocess.run()
    pass


def unblock_ip(ip_address):
    """Remove iptables DROP rule for the given IP."""
    cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    # TODO: implement with subprocess.run()
    pass
