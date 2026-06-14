# Aegis Entropy — Deception & Active Defense Module

Autonomous active defense framework integrating **Moving Target Defense (MTD)**, **High-Interaction Deception**, **Protocol Sabotage**, and **IP Blocking**. All subsystems feed telemetry to the Flask dashboard via dual logging (local JSONL + HTTP POST).

---

## Subsystems

### 1. High-Interaction Deception (`core_deception.py`)
Async TCP honeypot with 5 personality profiles routed deterministically by port (`port % 5`):
- Profile 0: Simulated Data Leak (fake env vars with credentials)
- Profile 1: Interactive Shell Mimicry (denies all commands)
- Profile 2: Credential Harvesting (captures login attempts)
- Profile 3: SSH Decoy with Latency (delays responses)
- Profile 4: Tool-Breaker (infinite JSON payload to exhaust scanners)

**ML Integration:** Exposes `get_honeypot_flag(src_ip) -> int` which returns 1 if the source IP has interacted with any honeypot port. This feeds `config.FEATURE_NAMES[9]` ("shadow_node_interaction") in the real-time ML pipeline.

**Port Range:** 1000-1100 (hardcoded in `__main__` block).

### 2. Moving Target Defense (`network_mutator.py`)
Intercepts outgoing TCP packets via NetfilterQueue and randomizes TTL + TCP Window size across 4 OS profiles (Windows, Cisco, Linux, Solaris). Invalidates automated OS fingerprinting (Nmap, ZMap).

**ML Integration:** Exposes `compute_mtd_port_delta(targeted_port, active_port) -> int` which computes the absolute port offset. This feeds `config.FEATURE_NAMES[10]` ("mtd_port_delta") in the real-time ML pipeline.

**Requires:** `sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1`

### 3. Protocol Sabotage & Tarpitting (`traffic_shaper.py`)
Sniffs incoming TCP probes and crafts deceptive SYN-ACK responses with:
- **Window Jitter:** Forces attackers into TCP Persist Timer state (window=0)
- **MSS Sabotage:** Limits segment size to 48/128/256 bytes, crippling throughput

Neutralizes SYN, FIN, NULL, and XMAS scanning techniques.

### 4. Response Engine (`monitor_interface.py`)
IP blocking via kernel blackhole + UFW deny. Provides `block_ip()` and `unblock_ip()` functions called by the Flask dashboard's `/api/block` endpoint.

**Mechanism:**
1. `ip route add blackhole <ip>` — drops packets at routing layer (zero-CPU)
2. `ufw insert 1 deny from <ip>` — persistent Layer 3 isolation

---

## Telemetry Architecture

All deception modules use **dual logging**:

```
deception module
  ├─ Local: mutation_logs.json (JSONL — one JSON line per event)
  └─ HTTP:  POST http://localhost:5000/api/honeypot_event → Flask dashboard
```

The response engine posts to:
```
  POST http://localhost:5000/api/block → Flask dashboard + kernel blackhole
```

---

## Prerequisites

* Linux Kernel 5.x+
* Python 3.9+
* Required libraries: `scapy`, `netfilterqueue`, `asyncio`
* **Root/sudo privileges** required for:
  * `network_mutator.py` (NetfilterQueue)
  * `traffic_shaper.py` (raw packet send)
  * `monitor_interface.py` (ip route, ufw)

### Running as Root

The Flask dashboard must run with sudo to enable IP blocking:

```bash
sudo python dashboard/app.py
```

Or configure passwordless sudo for the specific commands:
```
# /etc/sudoers.d/aegis
your_user ALL=(root) NOPASSWD: /sbin/ip route add blackhole *, /sbin/ip route del blackhole *
your_user ALL=(root) NOPASSWD: /usr/sbin/ufw insert *, /usr/sbin/ufw delete *
```

### MTD Hook

Before running `network_mutator.py`, route outgoing traffic to the mutation queue:
```bash
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1
```

---

## Running

```bash
# From project root:

# 1. Start the dashboard (with sudo for blocking)
sudo python dashboard/app.py

# 2. Start the honeypot listeners (ports 1000-1100)
python -m deception.core_deception

# 3. Start the MTD engine (requires iptables NFQUEUE rule)
sudo python -m deception.network_mutator

# 4. Start the tarpit (optional — requires root for raw packet send)
sudo python -m deception.traffic_shaper
```
