# AEGIS — AI-Powered Cyber Deception & Threat Intelligence Platform

> **Detect. Deceive. Deny.**

AEGIS is an integrated cyber defense platform combining AI-based intrusion detection with polymorphic honeypots, protocol tarpits, and Moving Target Defense (MTD).

---

## 🏗️ Project Structure (Clean Rebuild)

This repository serves as the central integration point. All placeholder stubs have been removed. Individual components are organized into dedicated folders where each member can drop their work:

```
Portscan_IDS/
├── config.py                  ← Shared configuration and data contract
├── requirements.txt           ← Unified project dependencies
├── .gitignore                 ← Git exclusion patterns
│
├── dashboard/                 ← Adil's Dashboard implementation
│   ├── app.py                 ← Flask web app with Socket.IO
│   ├── templates/             ← HTML dashboard template
│   └── static/                ← CSS styles and D3.js visualization scripts
│
├── detection/                 ← Khadija's Machine Learning space
│   └── README.md              ← Guided instructions for ML integration
│
├── deception/                 ← El Yazid's Deception & MTD space
│   └── README.md              ← Guided instructions for Deception/MTD integration
│
├── capture/                   ← Moulay Anas's Packet Capture space
│   └── README.md              ← Guided instructions for capture pipeline
│
└── bridge/                    ← Integration bridge scripts
    └── README.md              ← Integration mapping documentation
```

---

## 👥 Integration and Merge Strategy

To keep development clean, each member works on their own repository or branch, and drops their completed code into their designated folder inside this repo:

### 1. Pôle 1 — Machine Learning Detection (Khadija)
- **Repo source:** `https://github.com/KIKO123k/AegisEntropy`
- **Integration destination:** `detection/`
- **Steps:** Copy model training pipelines, preprocessing scripts, and trained `.pkl` / `.joblib` files to the `detection/` folder. Ensure the model expects the exactly **12 features** defined in `config.py`.

### 2. Pôle 2 — Deception & MTD Engine (El Yazid)
- **Repo source:** `https://github.com/MrGray17/Aegis_Entropy`
- **Integration destination:** `deception/`
- **Steps:** Copy the deception engine, shaper, network mutator, and monitor terminal CLI to the `deception/` folder. Ensure all modules import settings (e.g. `DECEPTION_LOG_FILE`) from the top-level `config.py`.

### 3. Pôle 3 — Network Capture & Feature Extraction (Moulay Anas)
- **Integration destination:** `capture/`
- **Steps:** Build the Scapy packet capture script inside `capture/` to sniff traffic and compute the 12 features in real time.

### 4. Pôle 4 & 5 — Dashboard & Project Management (Adil & Collaborators)
- **Integration destination:** `dashboard/` and `bridge/`
- **Steps:** Finalize log bridge (`bridge/log_bridge.py`) to link Yazid's deception logs to the web interface.

---

## 🚀 Running the Dashboard (Mock Mode)

You can run the web dashboard in mock mode to test UI interactions, animations, and the D3 heatmap layout without starting the network sensors:

```bash
# Install dependencies
pip install -r requirements.txt

# Run in mock mode
python dashboard/app.py --mock
```
Open `http://localhost:5000` to view the cyber operations console.

---

## 📜 License
Academic Project — ENSA Kénitra — AI Module S2 — 2026
