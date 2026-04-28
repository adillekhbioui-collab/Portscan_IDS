#!/bin/bash
# ============================================
# Pôle 3 — Moulay Anas
# Attack Simulation: Nmap Scan Scripts
# ============================================
# Run from Kali Linux against the IDS VM.
# Usage: bash run_nmap_scans.sh <TARGET_IP>
# ============================================

TARGET=${1:-"192.168.1.10"}

echo "=== SYN Stealth Scan ==="
nmap -sS -p 1-1000 $TARGET

echo "=== TCP Connect Scan ==="
nmap -sT -p 1-1000 $TARGET

echo "=== UDP Scan ==="
nmap -sU --top-ports 100 $TARGET

echo "=== XMAS Scan ==="
nmap -sX -p 1-1000 $TARGET

echo "=== ACK Scan ==="
nmap -sA -p 1-1000 $TARGET

echo "=== Slow Scan (1 probe/sec) ==="
nmap -sS --scan-delay 1s -p 1-100 $TARGET

echo "=== All scans complete ==="
