<div align="center">

# AEGIS

### **Adaptive Entropy-based Gateway for Intrusion Suppression**

<br>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0+-FF6F00?style=flat-square&logo=xgboost&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-6DC849?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0+-000000?style=flat-square&logo=flask&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Kali+%2F+Ubuntu-E95420?style=flat-square&logo=linux&logoColor=white)

**Real-time network intrusion detection with ML-driven classification and moving target defense.**

ENSA Kenitra &middot; AI Module &middot; Semester 2 &middot; 2026

</div>

---

## What is AEGIS?

AEGIS is a two-machine network defense system. A **Kali** attacker VM launches port scans against an **Ubuntu Server** running the AEGIS engine. The system captures live traffic, classifies it with trained ML models in real time, and automatically deploys deception tactics against detected attackers &mdash; all visualized on a live SOC dashboard.

```
+----------------------+          +-----------------------------------------------+
|   ATTACKER (KALI)    |  TCP     |              DEFENSE (UBUNTU)                |
|                      | -------> |                                               |
|  nmap / nse / custom |  scan    |  +---------+  +----------+  +-----------+    |
|                      |          |  | Capture |->|   ML     |->| Deception |    |
|                      |          |  | (Scapy) |  | (RF+XGB) |  |  (MTD)    |    |
|                      |          |  +---------+  +----------+  +-----------+    |
|                      |          |       |              |              |          |
|                      |          |       v              v              v          |
|                      |          |  +--------------------------------------------+ |
|                      |          |  |        SOC Dashboard (Flask + Socket.IO)  | |
|                      |          |  |           http://ubuntu:5000              | |
|                      |          |  +--------------------------------------------+ |
+----------------------+          +-----------------------------------------------+
```

---

## Results

All three models trained on the **CICIDS2017 PortScan** dataset (286K flow records) with **11 features** (9 from Data Dictionary + 2 MTD placeholders).

| Model | Accuracy | F1-Score | Precision | Recall | FPR | AUC-ROC |
|:------|:--------:|:--------:|:---------:|:------:|:---:|:-------:|
| **XGBoost** | **99.914%** | **99.923%** | 99.909% | 99.937% | **0.11%** | 0.999904 |
| **Random Forest** | 99.911% | 99.920% | 99.909% | 99.931% | **0.11%** | 0.999684 |
| Isolation Forest | 24.627% | 9.464% | 14.184% | 7.101% | 53.53% | 0.000 |

> Both supervised models trained with **11 features** exceed the success criteria: **F1 >= 88%**, **Accuracy >= 90%**, **FPR < 6%**.

---
## Project Structure

```
Portscan_IDS/
|
|-- config.py                          Central configuration
|
|-- capture/                           Data Acquisition
|   +-- fetch_and_align_datasets.py    CICIDS2017 dataset ingestion
|   +-- raw_datasets/                  Downloaded CSV files
|
|-- detection/                         ML Detection Engine
|   +-- src/
|   |   +-- data_preprocessing.py      Cleaning, outlier removal, log transforms
|   |   +-- feature_selection.py       13-feature mapping from Data Dictionary
|   |   +-- modeltrain.py              RF + XGBoost + Isolation Forest training
|   |   +-- evaluate_model.py          6-metric evaluation + confusion matrices
|   |   +-- predict.py                 Real-time inference on live captures
|   |   +-- cicids2017_pipeline.py     End-to-end 8-step pipeline
|   |   +-- config.py                  Detection-specific config
|   +-- pipeline_output/               Trained models, scalers, metrics
|
|-- deception/                         Moving Target Defense
|   +-- core_deception.py              Attacker redirection, blacklisting
|   +-- network_mutator.py             Port rotation to shuffle honeypot surface
|   +-- traffic_shaper.py              NetfilterQueue packet mutation
|   +-- monitor_interface.py           Terminal-based deception telemetry
|
|-- bridge/                            Inter-module Communication
|   +-- bridge.py                      AegisBridge: ML -> dashboard + defense
|   +-- nmap_parser.py                 Nmap XML/JSON -> feature extraction
|   +-- test_pipeline.py               End-to-end integration test
|
|-- dashboard/                         SOC Dashboard
|   +-- app.py                         Flask + Socket.IO backend
|   +-- templates/index.html           Real-time dark-theme UI
|   +-- static/style.css               Custom SOC aesthetic
|
|-- demo/                              Live Demo Scripts
|   +-- ubuntu_setup.sh                One-click Ubuntu Server setup
|   +-- kali_attack.sh                 5-phase attack simulation
|   +-- kali_custom_scanner.py         Low-rate stealth scanner
|
+-- requirements.txt                   All dependencies
```

---
## ML Pipeline

The detection pipeline follows a rigorous 8-step process:

```
1. FETCH     Download CICIDS2017 PortScan CSV (286,467 flows x 79 features)
      |
2. CLEAN     Strip column names, replace inf -> NaN, median imputation
      |
3. SELECT    Map 13 Data Dictionary features -> 9 CSV columns + 2 placeholders
      |
4. OUTLIER   IQR-based detection + Winsorization capping
      |
5. SKEW      Log1p transform for features with |skewness| > 1.0
      |
6. SPLIT     80/20 stratified train/test (228,802 / 57,294)
      |
7. BALANCE   SMOTE oversampling on training set only (no data leakage)
      |
8. TRAIN     Random Forest (100 trees) + XGBoost (lr=0.1, depth=6)
             + Isolation Forest (unsupervised baseline)
             Models trained on 11 features only.
```

**Feature set (11 total — 9 CSV features + 2 MTD placeholders):**

| # | Feature | Source | Purpose |
|---|---------|--------|---------|
| 1 | Destination Port | CSV | Proxy for distinct dst ports |
| 2 | Flow Duration | CSV | Scan speed indicator |
| 3 | Total Fwd Packets | CSV | Volume signal |
| 4 | SYN Flag Count | CSV | Port scan signature |
| 5 | RST Flag Count | CSV | Closed port response |
| 6 | ACK Flag Count | CSV | Handshake completion |
| 7 | Flow IAT Mean | CSV | Inter-arrival timing |
| 8 | Bwd Packet Length Mean | CSV | Response size |
| 9 | Init_Win_bytes_forward | CSV | TCP window size |
| 10 | MTD Port Delta | Placeholder | Future MTD integration |
| 11 | Shadow Node Interaction | Placeholder | Future honeypot integration |

---
## Deception Subsystem

Based on [Aegis Entropy](https://github.com/MrGray17/Aegis_Entropy) &mdash; Moving Target Defense:

| Module | What It Does |
|--------|-------------|
| `core_deception.py` | Redirects attackers to decoy ports via iptables REDIRECT, auto-blacklists after threshold |
| `network_mutator.py` | Rotates the honeypot surface every 30s, shuffles active ports |
| `traffic_shaper.py` | NFQUEUE hook mutates outgoing TCP destination ports in real-time |
| `monitor_interface.py` | Terminal-based telemetry dashboard for the deception layer |

---

## Quick Start

### 1. Clone and install
```bash
git clone https://github.com/MrGray17/Portscan_IDS.git
cd Portscan_IDS
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 2. Train models (one-time)
```bash
python detection/src/cicids2017_pipeline.py
```

### 3. Start the dashboard
```bash
python dashboard/app.py
# Open http://localhost:5000
```

### 4. Run a live demo (two VMs)
```bash
# Ubuntu Server:
bash demo/ubuntu_setup.sh

# Kali Linux:
bash demo/kali_attack.sh 192.168.56.10
```

---

## Configuration

All paths, ports, and thresholds in `config.py`:

```python
DATA_DIR              = "data"
DETECTION_LOG_FILE    = "data/detection_logs.json"
DECEPTION_LOG_FILE    = "data/deception_logs.json"
DECEPTION_PORT_START  = 1000
DECEPTION_PORT_END    = 1100
BAN_THRESHOLD         = 10
DASHBOARD_REFRESH_MS  = 2000
CONFIDENCE_THRESHOLD  = 0.95
ALERT_THRESHOLD       = 0.80
```

---

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| SMOTE on train only | Prevents data leakage from synthetic test samples |
| IQR capping over removal | Preserves valuable attack data, reduces bias |
| Median imputation over mean | Robust to skewed network traffic distributions |
| Log1p for skewed features | Handles zeros, preserves order, reduces extreme value influence |
| Stratified split | Maintains 55/45 class ratio in both train and test |
| 2 MTD placeholders | Architecture ready for real-time honeypot port delta integration |
| Isolation Forest on unsupervised path | Separate training without SMOTE (unsupervised algorithm) |

---

## Team

| Name | Role |
|------|------|
| Adil Lekhbioui | ML pipeline, data preprocessing, model training & evaluation |
| Khadija Nafia | ML pipeline co-development |
| El Yazid Hammoubel | Deception subsystem (Aegis Entropy), dashboard, integration, config |
| Anas El Kartouti | Documentation and report writing |
| Anas Moulay | AI integration in virtual machines |

---

## License

Academic use only &mdash; ENSA Kenitra
