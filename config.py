# ============================================
# AEGIS — Shared Configuration
# ============================================
# This file is the SINGLE SOURCE OF TRUTH for all
# shared settings. Every module imports from here.
# ============================================

import os

# --- Project Paths ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "detection", "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")

# --- Model Files ---
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgb_model.pkl")
IF_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")

# --- Feature Vector Definition ---
# CRITICAL: This is the EXACT order of features expected by all models.
# Khadija (ML) trains with this order.
# Moulay Anas (Capture) outputs features in this order.
# Adil (Dashboard) passes features in this order.
# DO NOT CHANGE without notifying ALL team members.
FEATURE_NAMES = [
    "Destination Port",         # 0  - Destination port (proxy for distinct ports target)
    "Flow Duration",            # 1  - Duration of connection in microseconds
    "Total Fwd Packets",        # 2  - Total packets sent in forward direction
    "SYN Flag Count",           # 3  - Count of SYN flags in flow
    "RST Flag Count",           # 4  - Count of RST flags in flow
    "ACK Flag Count",           # 5  - Count of ACK flags in flow
    "Flow IAT Mean",            # 6  - Mean Inter-Arrival Time of flow
    "Bwd Packet Length Mean",   # 7  - Mean size of packets in backward direction
    "Init_Win_bytes_forward",   # 8  - Initial TCP Window size in forward direction
    "shadow_node_interaction",  # 9  - Binary (0/1): Has the source IP hit a honeypot?
    "mtd_port_delta"            # 10 - Integer: Port offset from current active MTD port
]

FEATURE_COUNT = len(FEATURE_NAMES)  # 11

# --- Detection Thresholds ---
CONFIDENCE_THRESHOLD = 0.85    # Minimum confidence for automated response
ALERT_THRESHOLD = 0.60         # Minimum confidence to show alert on dashboard
MTD_TRIGGER_THRESHOLD = 0.85   # Confidence needed to trigger MTD rotation

# --- Time Windows ---
FAST_WINDOW_SECONDS = 10       # Fast scan detection window
SLOW_WINDOW_SECONDS = 60       # Slow scan detection window (Isolation Forest)

# --- Network Config ---
IDS_INTERFACE = "eth0"         # Network interface to capture on
HONEYPOT_IPS = [               # IPs of deployed honeypot nodes
    # "192.168.1.200",         # ← Update after VM setup
]

# --- Dashboard ---
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DASHBOARD_REFRESH_MS = 2000    # Socket.IO push interval (milliseconds)

# --- Blocking ---
AUTO_UNBLOCK_MINUTES = 30      # TTL for iptables DROP rules

# --- Logging ---
DETECTION_LOG_FILE = os.path.join(DATA_DIR, "detection_logs.json")
DECEPTION_LOG_FILE = os.path.join(DATA_DIR, "deception_logs.json")
