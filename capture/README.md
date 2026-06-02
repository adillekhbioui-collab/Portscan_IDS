# Pôle 3 — Packet Capture Pipeline (Moulay Anas)

This directory is reserved for Moulay Anas's real-time packet capture and feature extraction pipeline.

## Integration Guidelines

1. **Sniffing**: Use Scapy or a similar packet sniffer to capture live network traffic on the interface defined in `config.py`.
2. **Feature Extraction**: Aggregate packets per source IP over time windows (e.g., 10 seconds and 60 seconds) and calculate the **12 features** defined in `config. FEATURE_NAMES`.
3. **Pipeline**: Hand the computed feature vectors to the loaded machine learning model from the `detection/` folder, then POST results to the Flask backend `/api/alert` endpoint when a port scan is classified.
