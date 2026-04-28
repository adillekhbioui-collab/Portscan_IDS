# AEGIS — AI-Powered Cyber Deception & Threat Intelligence Platform

> **Detect. Deceive. Deny.**

AI-Based Intrusion Detection & Response System for Port Scanning & Network Reconnaissance — integrating ML Detection, Honeypot Deception, and Moving Target Defense.

## 🏗️ Project Structure

```
Portscan_IDS/
├── config.py                  ← Shared settings (paths, thresholds, feature order)
├── requirements.txt           ← All pip dependencies
│
├── data/                      ← Datasets (NOT pushed — download locally)
├── models/                    ← ML training scripts + saved .pkl models
│   ├── preprocess.py
│   ├── train_rf.py
│   ├── train_xgboost.py
│   ├── isolation_forest.py
│   ├── evaluate.py
│   └── saved/                 ← Trained model files (.pkl)
│
├── capture/                   ← Scapy packet capture + feature extraction
│   ├── capture_pipeline.py
│   └── feature_utils.py
│
├── honeypot/                  ← Cowrie/Dionaea config + log parser
│   ├── cowrie_config/
│   └── honeypot_parser.py
│
├── response/                  ← Blocking + MTD engines
│   ├── response_engine.py
│   └── mtd_engine.py
│
├── dashboard/                 ← Flask + Socket.IO + D3.js web interface
│   ├── app.py
│   ├── static/
│   └── templates/
│
├── simulation/                ← Nmap attack scripts + results
│   └── run_nmap_scans.sh
│
└── docs/                      ← BRD, report, slides
```

## 👥 Team & Branch Strategy

| Member | Branch | Module |
|---|---|---|
| Khadija | `feature/ml-pipeline` | AI & Machine Learning (Pôle 1) |
| El Yazid | `feature/mtd-honeypot` | MTD Engine & Honeypots (Pôle 2) |
| Moulay Anas | `feature/network-capture` | Network Architecture & Capture (Pôle 3) |
| Adil | `feature/dashboard` | Dashboard & Automated Response (Pôle 4) |
| El Kartouti Anas | `feature/docs-validation` | Methodology, Validation & PM (Pôle 5) |

### Git Workflow

```bash
# 1. Pull latest main
git checkout main && git pull

# 2. Switch to your branch
git checkout feature/your-branch

# 3. Merge main into your branch (get team updates)
git merge main

# 4. Work, commit, push
git add . && git commit -m "description" && git push origin feature/your-branch

# 5. When feature complete → open Pull Request on GitHub → team reviews → merge to main
```

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/adillekhbioui-collab/Portscan_IDS.git
cd Portscan_IDS

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Download datasets (see data/README.md)
```

## 📅 Timeline

- **Weeks 1–2:** Design + Data Preparation
- **Weeks 3–4:** Model Training + Dashboard + MTD/Honeypot
- **Week 5:** Testing & Attack Simulation
- **Week 6:** Validation, Report & Demo

## 📜 License

Academic Project — ENSA Kénitra — AI Module S2 — 2026
