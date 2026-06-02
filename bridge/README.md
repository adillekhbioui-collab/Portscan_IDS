# Pôle 4 & 5 — Integration Bridge (Adil & Collaborators)

This directory is reserved for the scripts that bridge and integrate the different poles together.

## Integration Components:

1. **Log Bridge (`log_bridge.py`)**: A daemon script that polls Yazid's `mutation_logs.json` and forwards new events (decoy hits, tarpit entrapments, shell commands, credentials, MTD mutations) directly to the Flask dashboard via Socket.IO/REST.
2. **Alert Router**: Logic that coordinates auto-blocking decisions at the firewall/routing table level and syncs the state back to the dashboard's active scanners list.
