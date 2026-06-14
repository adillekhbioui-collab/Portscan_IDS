#!/bin/bash
# AEGIS Attack Simulation Script
# Run from Kali Linux against Ubuntu Victime

TARGET_IP="${1:-192.168.100.20}"
ATTACKER_IP="192.168.100.10"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}=== AEGIS Attack Simulation ===${NC}"
echo -e "Target: ${TARGET_IP}"
echo -e "Attacker: ${ATTACKER_IP}"
echo ""

# Phase 1: Fast SYN scan
echo -e "${YELLOW}[Phase 1] Fast Nmap SYN scan (1000 ports)${NC}"
nmap -sS -T5 --top-ports 1000 "$TARGET_IP" 2>/dev/null
sleep 3

# Phase 2: Service version scan
echo -e "${YELLOW}[Phase 2] Service version detection${NC}"
nmap -sV -T4 -p 22,80,443,8080,8443 "$TARGET_IP" 2>/dev/null
sleep 3

# Phase 3: Slow stealth scan
echo -e "${YELLOW}[Phase 3] Slow stealth scan (T1, 60s)${NC}"
nmap -sS -T1 --max-rate 1 "$TARGET_IP" 2>/dev/null &
SLOW_PID=$!
sleep 60
kill $SLOW_PID 2>/dev/null
wait $SLOW_PID 2>/dev/null
sleep 3

# Phase 4: OS detection
echo -e "${YELLOW}[Phase 4] OS detection${NC}"
nmap -O --osscan-guess "$TARGET_IP" 2>/dev/null
sleep 3

# Phase 5: UDP scan (common ports)
echo -e "${YELLOW}[Phase 5] UDP scan (top 20 ports)${NC}"
nmap -sU --top-ports 20 "$TARGET_IP" 2>/dev/null

echo ""
echo -e "${GREEN}=== Attack simulation complete ===${NC}"
echo -e "Check the AEGIS dashboard at http://192.168.100.20:5000"
