# ============================================
# AEGIS — Shared Configuration
# ============================================
# This file is the SINGLE SOURCE OF TRUTH for all
# shared settings. Every module imports from here.
# ============================================

import os

# --- Project Paths ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")

# --- Model Files ---
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgb_model.pkl")
IF_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest.pkl")

# --- Feature Vector Definition ---
# CRITICAL: This is the EXACT order of features expected by all models.
# Khadija (ML) trains with this order.
# Moulay Anas (Capture) outputs features in this order.
# Adil (Dashboard) passes features in this order.
# DO NOT CHANGE without notifying ALL team members.
FEATURE_NAMES = [
    "distinct_dst_ports",      # 0  - # unique destination ports per source
    "syn_flag_count",          # 1  - SYN packets without completing handshake
    "rst_flag_count",          # 2  - RST responses from closed ports
    "flow_duration",           # 3  - Duration of probe connection (seconds)
    "total_fwd_packets",       # 4  - Packets per flow from scanner
    "iat_mean",                # 5  - Mean inter-arrival time between probes
    "port_range_entropy",      # 6  - Shannon entropy of destination ports
    "ack_flag_count",          # 7  - ACK packets without prior SYN
    "unique_dst_ips",          # 8  - # distinct destination hosts contacted
    "bwd_packet_length",       # 9  - Response packet size
    "ttl_value",               # 10 - Time-to-live in IP header
    "honeypot_flag",           # 11 - Binary: source IP contacted a honeypot?
]

FEATURE_COUNT = len(FEATURE_NAMES)  # 12

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
