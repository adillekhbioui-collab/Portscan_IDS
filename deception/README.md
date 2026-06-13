## Deception & Moving Target Defense (MTD)

Based on [Aegis_Entropy](https://github.com/MrGray17/Aegis_Entropy), integrated into the Portscan_IDS architecture.

### Modules

| File | Role |
|------|------|
| `src/core_deception.py` | Attacker redirection, phantom network deployment, auto-blacklisting |
| `src/network_mutator.py` | Port rotation — shuffles the honeypot surface at configurable intervals |
| `src/traffic_shaper.py` | NetfilterQueue hook — mutates outgoing TCP ports via NFQUEUE |
| `src/monitor_interface.py` | Terminal dashboard — live threat level & event stream |

### Configuration (config.py)

```
DECEPTION_PORT_START = 1000
DECEPTION_PORT_END   = 1100
BAN_THRESHOLD        = 10
DECEPTION_INTERFACE  = <IDS_INTERFACE>
DECEPTION_LOG_FILE   = data/deception_logs.json
```

### Running

```bash
# 1. Set up NFQUEUE (requires root)
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1

# 2. Start the traffic shaper
sudo python3 deception/src/traffic_shaper.py

# 3. Start the port mutator (background)
python3 deception/src/network_mutator.py

# 4. Launch the monitor
python3 deception/src/monitor_interface.py
```

### Data Flow

```
Attacker ──scan──▶ IDS detects ──▶ core_deception.log_event()
                    │                      │
                    ▼                      ▼
              predict.py             deception_logs.json
                    │                      │
                    ▼                      ▼
              bridge/              monitor_interface.py
              (emit via Socket.IO)   (terminal dashboard)
```

### Log Schema (deception_logs.json)

```json
{
  "timestamp": "2026-06-13T10:30:00",
  "event_type": "REDIRECT",
  "src_ip": "192.168.1.100",
  "original_port": 22,
  "decoy_port": 1042
}
```

### Prerequisites

- Root / sudo for iptables and NFQUEUE
- `netfilterqueue` Python package (`pip install netfilterqueue`)
- Linux kernel with nfnetlink_queue module
