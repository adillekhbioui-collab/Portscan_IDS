# Pôle 2 — Deception & MTD Engine (El Yazid)

This directory is reserved for El Yazid's Aegis Entropy deception modules.

## Deception Modules Included:

1. **Honeypot (`core_deception.py`)**: Polymorphic high-interaction decoy.
2. **TCP Tarpit (`traffic_shaper.py`)**: Slows scanner traffic with window jitter and tiny MSS.
3. **MTD OS Randomizer (`network_mutator.py`)**: Intercepts packets via `NFQUEUE` to mutate TTL and Window Size.
4. **Command Console (`monitor_interface.py`)**: Threat analyzer and auto-blocking engine.

## Integration Guidelines

1. Ensure the logs are written to the path configured in `config.py` (`DECEPTION_LOG_FILE`).
2. Make sure any Linux/iptables configurations are parameterized or well-documented so they don't break local cross-platform development.
