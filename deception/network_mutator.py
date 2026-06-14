import os
import sys
import json
import random
import datetime
import urllib.request
from scapy.all import IP, TCP
from netfilterqueue import NetfilterQueue

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config


def log_event(event_type, src_port, new_ttl):
    """
    Dual logging:
      1. Local JSONL file (append one JSON line per event)
      2. HTTP POST to the Flask dashboard (best-effort, 2s timeout)
    """
    new_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event_type,
        "ip": "LOCAL_OUTBOUND",
        "details": f"Port: {src_port} | Mutated TTL: {new_ttl}"
    }

    # 1. Local JSONL log
    os.makedirs(os.path.dirname(config.DECEPTION_LOG_FILE), exist_ok=True)
    with open(config.DECEPTION_LOG_FILE, 'a') as f:
        f.write(json.dumps(new_entry) + "\n")

    # 2. POST to dashboard (best-effort)
    try:
        payload = json.dumps({
            "src_ip": "LOCAL_OUTBOUND",
            "service": event_type,
            "commands": [],
            "credentials": [],
            "timestamp": new_entry["timestamp"]
        }).encode("utf-8")
        req = urllib.request.Request(
            "http://localhost:5000/api/honeypot_event",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=2.0)
    except Exception:
        pass


# In-memory MTD state: tracks port offsets for ML integration
_current_port_offset = 0

def compute_mtd_port_delta(src_ip=None):
    """
    Returns the current MTD port offset (feature index 10 in the ML pipeline).
    This value indicates how far the active service ports have been rotated
    from their baseline positions. Used by the bridge to populate the
    'mtd_port_delta' feature for ML classification.
    """
    return _current_port_offset


def mutate_packet(packet):
    """
    Intercepts and modifies outgoing TCP/IP packets at Layer 3/4.
    Alters Time-To-Live (TTL) and TCP Window sizes to spoof OS fingerprints,
    creating a Moving Target Defense (MTD) effect against reconnaissance.
    """
    try:
        scapy_pkt = IP(packet.get_payload())

        if scapy_pkt.haslayer(TCP):
            # Define realistic OS profiles to confuse Nmap OS Detection
            # Windows: TTL 128 | Cisco IOS: TTL 255 | Linux: TTL 64 | Solaris: TTL 254
            os_profiles = [
                {"os": "Windows", "ttl": 128, "window": random.randint(8000, 8192)},
                {"os": "Cisco", "ttl": 255, "window": random.randint(4000, 4128)},
                {"os": "Linux", "ttl": 64,  "window": random.randint(5800, 5840)},
                {"os": "Solaris", "ttl": 254, "window": random.randint(8100, 8192)}
            ]

            # Select a random OS profile for this specific packet
            profile = random.choice(os_profiles)
            scapy_pkt.ttl = profile["ttl"]
            scapy_pkt[TCP].window = profile["window"]

            # Delete checksums to force Scapy to recalculate them accurately
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            # Inject the mutated packet back into the network stream
            packet.set_payload(bytes(scapy_pkt))

            print(f"[*] Polymorphic Shift: Spoofing {profile['os']} (TTL: {profile['ttl']}, Win: {profile['window']})")
            log_event("MTD_MUTATION", scapy_pkt[TCP].sport, profile['ttl'])

    except Exception as e:
        # Failsafe: Log the error but do not disrupt network flow
        pass

    finally:
        # Release the packet to continue its journey through the Linux kernel
        packet.accept()

if __name__ == "__main__":
    print("[*] Initializing Aegis Morph Polymorphic Engine (MTD)...")
    print("[*] Hooking into Netfilter Queue 1 for dynamic OS signature spoofing.")

    try:
        nfqueue = NetfilterQueue()
        # Bind to queue 1, matching the iptables NFQUEUE rule
        nfqueue.bind(1, mutate_packet)
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Terminating Polymorphic Engine.")
    except Exception as e:
        print(f"[CRITICAL] Engine failure: {e}")
        print("[!] Ensure iptables rules are configured and running as root.")
