# AEGIS — Live Demo Guide

Simulate a real port scan attack from Kali Linux against the AEGIS IDS running on Ubuntu Server.

## Prerequisites

- **VMware Workstation** (or VirtualBox)
- **Ubuntu Server VM** — 4GB RAM, 2 CPUs, VirtualBox Internal Network lab-cyber `192.168.100.0/24`
- **Kali Linux VM** — 2GB RAM, same VirtualBox Internal Network lab-cyber

## Network Setup

1. In VMware: **Edit → Virtual Network Editor → Add Network → VMnet8 (NAT)**
2. Set subnet to `192.168.100.0/24`, disable DHCP
3. Ubuntu Server VM: set static IP `192.168.100.20`
4. Kali VM: set static IP `192.168.100.10`

```bash
# Ubuntu Server (inside VM):
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.100.20/24
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"

# Kali (inside VM):
sudo ip addr add 192.168.100.10/24 dev eth0
```

## Step 1: Set Up AEGIS (Ubuntu Server)

```bash
# Copy the demo scripts to your Ubuntu Server
scp demo/* your_user@192.168.100.20:~/AEGIS/

# SSH into Ubuntu Server
ssh your_user@192.168.100.20

# Run setup
chmod +x ~/AEGIS/demo/ubuntu_setup.sh
~/AEGIS/demo/ubuntu_setup.sh
```

The dashboard will be at: **http://192.168.100.20:5000**

## Step 2: Run Attacks (Kali)

```bash
# Copy attack scripts to Kali
scp demo/* your_user@192.168.100.10:~/attacks/

# SSH into Kali
ssh your_user@192.168.100.10

# Run the attack simulation
chmod +x ~/attacks/kali_attack.sh
~/attacks/kali_attack.sh 192.168.100.20
```

### What Each Phase Does

| Phase | Tool | Description | What AEGIS Sees |
|-------|------|-------------|-----------------|
| 1 | Nmap -T4 -sS | Fast SYN scan, 1000 ports | High-rate attack → BLOCKED |
| 2 | Nmap -sV | Service version probe | Moderate scan → detected |
| 3 | Custom Python | Slow stealth scan, 60s | Low-and-slow → Isolation Forest |
| 4 | Nmap -O | OS fingerprinting | Reconnaissance → flagged |
| 5 | Nmap -sU | UDP scan, top 20 ports | Different protocol → detected |

## Step 3: Watch the Dashboard

Open **http://192.168.100.20:5000** in your browser on the Ubuntu Server.

You should see:
- **Attacks Detected** counter increasing in real-time
- **Deception Redirects** when attackers hit honeypot ports
- **Threat Level** changing from LOW → MEDIUM → HIGH → CRITICAL
- **Event Tables** streaming live detection and deception events

## Architecture During Demo

```
Kali (192.168.100.10)          Ubuntu Server (192.168.100.20)
┌─────────────────┐           ┌──────────────────────────────┐
│  Nmap scans     │──TCP────▶│  Scapy capture (capture.py)  │
│  Custom scanner │           │         │                    │
│  UDP probes     │           │         ▼                    │
└─────────────────┘           │  predict.py (RF + XGBoost)   │
                              │         │                    │
                              │    ┌────┴────┐               │
                              │    │ ATTACK  │──▶ core_deception.py
                              │    │ BENIGN  │   (redirect to honeypot)
                              │    └─────────┘               │
                              │         │                    │
                              │         ▼                    │
                              │  dashboard/app.py            │
                              │  (Flask + Socket.IO :5000)   │
                              └──────────────────────────────┘
```

## Troubleshooting

**Dashboard not accessible?**
```bash
# Check if app is running
ps aux | grep app.py
# Restart if needed
cd ~/AEGIS && source venv/bin/activate && python dashboard/app.py &
```

**No detection events appearing?**
```bash
# Check if models exist
ls ~/AEGIS/models/saved/
# If empty, retrain: python detection/src/cicids2017_pipeline.py
```

**Kali can't reach Ubuntu Server?**
```bash
# Check IPs
ip addr show
# Ping test
ping 192.168.100.20
# Check firewall
sudo iptables -L -n
```

**Deception subsystem not working?**
```bash
# Needs root for iptables/NFQUEUE
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1
# Check netfilterqueue is installed
pip install netfilterqueue
```
