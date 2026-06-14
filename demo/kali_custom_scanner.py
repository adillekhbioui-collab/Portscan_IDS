#!/usr/bin/env python3
# AEGIS Custom Low-Rate Scanner
# Generates stealthy scan traffic that triggers Isolation Forest detection.

import socket
import random
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.20"
PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 9090]
INTERVAL_MIN = 3.0
INTERVAL_MAX = 8.0


def scan(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect_ex((target, port))
        s.close()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    print(f"[*] Custom scanner targeting {TARGET}")
    print(f"[*] Ports: {PORTS}")
    print(f"[*] Interval: {INTERVAL_MIN}-{INTERVAL_MAX}s (low-rate)")
    scan_count = 0

    try:
        while True:
            port = random.choice(PORTS)
            result = scan(TARGET, port)
            scan_count += 1
            status = "OPEN" if result else "closed"
            print(f"  [{scan_count}] {TARGET}:{port} -> {status}")
            wait = random.uniform(INTERVAL_MIN, INTERVAL_MAX)
            time.sleep(wait)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {scan_count} scans")
