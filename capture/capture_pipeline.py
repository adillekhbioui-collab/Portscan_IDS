# ============================================
# Pôle 3 — Moulay Anas
# Capture Pipeline: Scapy Packet Capture
# ============================================
# This script handles:
#   1. Sniff packets on config.IDS_INTERFACE using BPF filter
#   2. Aggregate per source IP over 10s and 60s windows
#   3. Compute the 12 features defined in config.FEATURE_NAMES
#   4. Output feature vectors for real-time classification
# ============================================

# TODO: Moulay Anas — implement this module
# Use: from scapy.all import sniff
# Use: config.FEATURE_NAMES for the exact feature order
# Output should be a dict or list matching the feature order in config.py
