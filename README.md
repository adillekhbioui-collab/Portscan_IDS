# AEGIS — Network Intrusion Detection & Deception System

Academic project — ENSA Kenitra — AI Module S2 — 2026

## Architecture

```
Portscan_IDS/
├── capture/                    # Data Acquisition Layer
│   ├── src/
│   │   ├── capture.py          # Scapy live packet capture
│   │   └── fetch_and_align_datasets.py  # Dataset ingestion (CICIDS2017, UNSW-NB15)
│   └── raw_datasets/           # Downloaded CSV datasets
├── detection/                  # Detection & Classification Layer
│   ├── src/
│   │   ├── train.py            # XGBoost & Random Forest training
│   │   ├── predict.py          # Real-time inference
│   │   └── cicids2017_pipeline.py  # Full ML pipeline (8-step)
│   └── pipeline_output/        # Trained models (.joblib), metrics, encoders
├── deception/                  # Deception & MTD Layer (Aegis Entropy)
│   └── src/
│       ├── core_deception.py   # Attacker redirection, phantom networks, blacklisting
│       ├── network_mutator.py  # Port rotation — Moving Target Defense
│       ├── traffic_shaper.py   # NetfilterQueue hook — real-time packet mutation
│       └── monitor_interface.py # Terminal dashboard for deception telemetry
├── dashboard/                  # Visualization Layer
│   ├── app.py                  # Flask + Socket.IO backend
│   ├── templates/index.html    # Dark-theme real-time dashboard
│   └── static/style.css        # AEGIS visual design
├── bridge/                     # Inter-module communication
│   └── event_bridge.py         # Socket.IO bridge: detection ↔ dashboard
├── config.py                   # Central configuration
└── requirements.txt            # Dependencies
```

## Modules

| Module | Source | Role |
|--------|--------|------|
| **Capture** | Scapy, CICIDS2017 pipeline | Live packet sniffing + dataset preparation |
| **Detection** | XGBoost, Random Forest | Binary classification (attack / benign) |
| **Deception** | Aegis Entropy (MTD) | Honeypot surface, port mutation, attacker redirection |
| **Dashboard** | Flask + Socket.IO | Real-time visualization of all subsystems |
| **Bridge** | Socket.IO | Connects detection alerts to dashboard |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run detection pipeline (trains models)
python detection/src/cicids2017_pipeline.py

# 3. Start the dashboard
python dashboard/app.py
# → http://localhost:5000

# 4. (Optional) Start deception subsystem (requires root)
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1
sudo python3 deception/src/traffic_shaper.py &
python3 deception/src/network_mutator.py &
python3 deception/src/monitor_interface.py
```

## Configuration

All paths, ports, and thresholds are in `config.py`:

```python
DATA_DIR            = "data"
DETECTION_LOG_FILE  = "data/detection_logs.json"
DECEPTION_LOG_FILE  = "data/deception_logs.json"
DECEPTION_PORT_START = 1000
DECEPTION_PORT_END   = 1100
BAN_THRESHOLD        = 10
REFRESH_MS           = 2000    # Dashboard push interval
```

## ML Pipeline (cicids2017_pipeline.py)

1. Fetch CICIDS2017 datasets (if missing)
2. Merge all daily CSVs into a single DataFrame
3. Clean column names, drop unused columns
4. Encode categorical features (Label → binary)
5. Train/test split (80/20, stratified)
6. Train XGBoost and Random Forest
7. Evaluate (accuracy, precision, recall, F1, ROC-AUC, confusion matrix)
8. Export artifacts: models, encoders, metrics JSON, sample predictions CSV

## Deception Subsystem (Aegis Entropy)

Based on [MrGray17/Aegis_Entropy](https://github.com/MrGray17/Aegis_Entropy):

- **core_deception.py** — Redirects attackers to decoy ports, deploys phantom subnets, auto-blacklists after BAN_THRESHOLD events
- **network_mutator.py** — Rotates the honeypot surface every 30s (configurable), shuffles active ports via iptables
- **traffic_shaper.py** — NFQUEUE hook that mutates outgoing TCP destination ports in real-time
- **monitor_interface.py** — Terminal-based telemetry dashboard for the deception layer

## Log Schema

**detection_logs.json:**
```json
{
  "timestamp": "2026-06-13T10:30:00",
  "src_ip": "192.168.1.100",
  "dst_port": 22,
  "prediction": 1,
  "label": 1,
  "action": "BLOCK"
}
```

**deception_logs.json:**
```json
{
  "timestamp": "2026-06-13T10:30:00",
  "event_type": "REDIRECT",
  "src_ip": "192.168.1.100",
  "original_port": 22,
  "decoy_port": 1042
}
```

## License

Academic use only — ENSA Kenitra
