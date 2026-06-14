# AEGIS - VM Implementation Guide

**Author:** Anas Moulay (VM Setup & Integration)
**Date:** June 2026
**Hypervisor:** VMware Workstation Pro
**Network:** NAT Network (192.168.56.0/24)

---

## Overview

This guide walks through setting up the complete AEGIS demonstration environment:

- **VM 1: Ubuntu Server** - Runs the AEGIS IDS engine, ML models, deception system, and dashboard
- **VM 2: Kali Linux** - Launches port scan attacks against Ubuntu Server
- **Host Machine** - Accesses the SOC dashboard via browser

```
  Host Browser (dashboard:5000)
       |
       v
  +-----------+     TCP scan      +------------------+
  |   Kali    | ----------------> | Ubuntu Server    |
  | .56.20    |                   | .56.10           |
  +-----------+                   | AEGIS IDS + MTD  |
                                  | Dashboard :5000  |
                                  +------------------+
```

---

## Prerequisites

| Item | Details |
|------|---------|
| VMware Workstation | Version 17+ recommended |
| Ubuntu Server ISO | 22.04 LTS or 24.04 LTS |
| Kali Linux ISO | 2024+ (kali-linux-2024.x-installer-amd64.iso) |
| Disk space | ~25 GB free for both VMs |
| RAM | 4 GB for Ubuntu, 2 GB for Kali |
| Internet | Required during setup (for apt/pip installs) |

---
## Part 1: VMware Network Configuration

### Step 1.1: Create the NAT Network

1. Open VMware Workstation
2. Go to **Edit > Virtual Network Editor**
3. Click **Change Settings** (requires admin)
4. Click **Add Network** and select **VMnet8**
5. Configure VMnet8:
   - **Subnet IP:** 192.168.56.0
   - **Subnet Mask:** 255.255.255.0
   - **NAT mode:** Enabled
   - **Use local DHCP:** UNCHECK this (we use static IPs)
6. Click **NAT Settings** and note the Gateway IP (usually 192.168.56.2)
7. Click **Apply** then **OK**

### Step 1.2: Verify Network

Open a terminal on your host machine and run:

```bash
# On Windows (PowerShell):
ipconfig
# Look for VMware Network Adapter VMnet8
# Should show: 192.168.56.1
```

If you see 192.168.56.1, the network is configured correctly.

---

## Part 2: Ubuntu Server VM (AEGIS Defense)

### Step 2.1: Create the VM

1. In VMware: **File > New Virtual Machine**
2. Select **Typical (recommended)**
3. Select **Installer disc image file (iso)** and browse to your Ubuntu Server ISO
4. Fill in the installation info:
   - **Full name:** AEGIS Admin
   - **Username:** aegis
   - **Password:** aegis123
   - **Hostname:** aegis-server
5. Disk: **50 GB** (dynamically allocated)
6. Customize hardware:
   - **Memory:** 4096 MB (4 GB)
   - **Processors:** 2 cores
   - **Network Adapter:** Select **Custom: Specific virtual network > VMnet8 (NAT)**
7. Click **Finish** and power on the VM

### Step 2.2: Ubuntu Server Installation

Follow the Ubuntu installer prompts:

1. Select language (English)
2. Select **Use an entire disk** - this is fine for the demo
3. Confirm the partition layout
4. Set your profile:
   - **Your name:** AEGIS Admin
   - **Your server's name:** aegis-server
   - **Username:** aegis
   - **Password:** aegis123
5. **SSH Setup:** Check **Install OpenSSH server** (IMPORTANT)
6. **Featured Server Snaps:** Skip (do not select any)
7. Wait for installation to complete
8. **Reboot** the VM
9. After reboot, press Enter to continue
10. You should see the login prompt

### Step 2.3: Configure Static IP

Log in with your credentials, then:

```bash
# Check current network interface name
ip addr show
# Usually 'ens160' or 'enp0s3' on VMware

# Set static IP
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.56.10/24
sudo nmcli con mod "Wired connection 1" ipv4.gateway 192.168.56.2
sudo nmcli con mod "Wired connection 1" ipv4.dns "8.8.8.8 8.8.4.4"
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"

# Verify
ip addr show
# Should show: 192.168.56.10/24

# Test internet
ping -c 3 8.8.8.8
```

### Step 2.4: Install System Dependencies

```bash
sudo apt update -y
sudo apt install -y git curl wget python3 python3-pip python3-venv \
    build-essential libnetfilter-queue-dev net-tools iptables-persistent
```

### Step 2.5: Clone the Repository

```bash
cd /home/aegis
git clone https://github.com/MrGray17/Portscan_IDS.git AEGIS
cd AEGIS
```

### Step 2.6: Set Up Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install imbalanced-learn xgboost gdown
```

### Step 2.7: Verify Models Are Present

```bash
# Check that trained models exist
ls -la models/saved/

# You should see:
#   rf_model.pkl
#   xgb_model.pkl
#   isolation_forest.pkl
#   scaler.pkl
#   feature_columns.json
#   evaluation_metrics.json

# If models are missing, retrain:
python detection/src/retrain_11features.py
```

### Step 2.8: Create Data Directory and Launch

```bash
mkdir -p data

# Start the dashboard (runs on port 5000)
source venv/bin/activate
python dashboard/app.py

# You should see:
# [AEGIS] Dashboard running on http://0.0.0.0:5000
```

### Step 2.9: Verify Dashboard Is Working

From your host machine, open a browser and go to:
```
http://192.168.56.10:5000
```

You should see the AEGIS SOC dashboard with:
- Top status bar showing 'SYSTEM OPERATIONAL'
- Threat level indicator (starts at LOW)
- 4 metric cards (Detected, Blocked, Redirected, Attack Rate)
- Architecture diagram showing data flow
- Two empty event tables (Detection Log, Deception Log)

**IMPORTANT:** Keep this terminal running. The dashboard must stay active.

---

## Part 3: Kali Linux VM (Attacker)

### Step 3.1: Create the VM

1. In VMware: **File > New Virtual Machine**
2. Select **Typical (recommended)**
3. Browse to your Kali Linux ISO
4. Select **Linux** as the guest OS, **Debian 12.x 64-bit** as the version
5. Name: **Kali-Attacker**, Location: wherever you have space
6. Disk: **30 GB** (dynamically allocated)
7. Customize hardware:
   - **Memory:** 2048 MB (2 GB)
   - **Processors:** 2 cores
   - **Network Adapter:** Select **Custom: Specific virtual network > VMnet8 (NAT)**
8. Click **Finish** and power on

### Step 3.2: Kali Installation

1. Select **Graphical Install**
2. Follow the installer (Language: English, Location: Morocco or your timezone)
3. Set hostname: **kali-attacker**
4. Set username: **kali**, password: **kali123**
5. Partitioning: **Use entire disk**
6. Software selection: Keep defaults (top 4 checked)
7. Install GRUB: Yes, to /dev/sda
8. Reboot when done

### Step 3.3: Configure Static IP

```bash
# Log in with kali/kali123

# Set static IP
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.56.20/24
sudo nmcli con mod "Wired connection 1" ipv4.gateway 192.168.56.2
sudo nmcli con mod "Wired connection 1" ipv4.dns "8.8.8.8 8.8.4.4"
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"

# Verify
ip addr show
# Should show: 192.168.56.20/24
```

### Step 3.4: Test Connectivity to Ubuntu Server

```bash
# Test connection to AEGIS server
ping -c 3 192.168.56.10

# If ping fails, check:
# 1. Both VMs are on VMnet8
# 2. Ubuntu firewall allows ICMP:
#    sudo ufw allow from 192.168.56.0/24
#    sudo ufw allow from 192.168.56.0/24 to any port 5000
```

### Step 3.5: Install Attack Tools

```bash
sudo apt update -y
sudo apt install -y nmap netcat-openbsd
```

### Step 3.6: Copy Attack Scripts to Kali

From your host machine, copy the demo scripts to Kali:

```bash
# From host PowerShell/CMD:
scp C:\path\to\Portscan_IDS\demo\kali_attack.sh kali@192.168.56.20:~/
scp C:\path\to\Portscan_IDS\demo\kali_custom_scanner.py kali@192.168.56.20:~/

# Or clone the repo on Kali:
git clone https://github.com/MrGray17/Portscan_IDS.git ~/AEGIS
```


---

## Part 4: Running the Demo

### Step 4.1: Start the Ubuntu Server (Defense)

```bash
# SSH into Ubuntu Server (from host or Kali):
ssh aegis@192.168.56.10

# Navigate to project and activate venv:
cd /home/aegis/AEGIS
source venv/bin/activate

# Start the dashboard:
python dashboard/app.py &

# You should see:
# [AEGIS] Dashboard running on http://0.0.0.0:5000
```

Open the dashboard in your host browser: **http://192.168.56.10:5000**

### Step 4.2: Run the Attack (Kali)

```bash
# SSH into Kali:
ssh kali@192.168.56.20

# Run the full attack simulation:
chmod +x ~/kali_attack.sh
~/kali_attack.sh 192.168.56.10
```

### What Happens During the Demo

```
Phase 1: Fast Nmap SYN scan (1000 ports)
  Kali sends rapid SYN packets to Ubuntu
  AEGIS Scapy capture sees the flood
  ML model (XGBoost) classifies as ATTACK
  Dashboard shows attacks counter increasing
  Threat level goes LOW -> MEDIUM -> HIGH

Phase 2: Service version scan
  More targeted probes, detected and logged

Phase 3: Slow stealth scan (60 seconds)
  Low-rate scanner to evade detection
  Tests Isolation Forest sensitivity

Phase 4: OS detection
  Nmap fingerprints the OS, flagged as recon

Phase 5: UDP scan
  Different protocol signature, detected as anomaly
```

### Step 4.3: Observe Results on Dashboard

Watch the dashboard at **http://192.168.56.10:5000** during the attack:

| What You See | What It Means |
|-------------|---------------|
| **DETECTED** counter increases | ML models are classifying attack traffic |
| **Threat Level** changes color | LOW (green) -> MEDIUM (yellow) -> HIGH (orange) |
| **DETECTION LOG** fills with rows | Each row = one classified network flow |
| **VERDICT** column shows ATTACK in red | The ML model flagged this as malicious |
| **ACTION** column shows BLOCK | The system auto-blocked the source IP |
| **DECEPTION LOG** shows REDIRECT | Attacker was redirected to honeypot port |

---

## Part 5: Network Diagram



---

## Part 6: Troubleshooting

| Problem | Solution |
|---------|----------|
| Kali cannot ping Ubuntu | Check both VMs are on VMnet8. Run ip addr show on both. |
| Dashboard not accessible | Make sure python dashboard/app.py is running. Run sudo ufw allow 5000 |
| No events on dashboard | Models may be missing. Run: python detection/src/retrain_11features.py |
| nmap not found on Kali | Run: sudo apt install nmap |
| Port 5000 blocked | Run: sudo ufw allow 5000 on Ubuntu Server |
| SSH connection refused | Run: sudo apt install openssh-server on Ubuntu |
| VMs cannot see each other | Both must be on VMnet8. Check VMware Network Editor. |

---

## Part 7: Quick Reference

### Ubuntu Server (AEGIS)

| Item | Value |
|------|-------|
| IP Address | 192.168.56.10 |
| Username | aegis |
| Password | aegis123 |
| SSH | ssh aegis@192.168.56.10 |
| Dashboard | http://192.168.56.10:5000 |
| Project Path | /home/aegis/AEGIS |
| Models Path | /home/aegis/AEGIS/models/saved/ |
| Start Command | source venv/bin/activate && python dashboard/app.py |

### Kali Linux (Attacker)

| Item | Value |
|------|-------|
| IP Address | 192.168.56.20 |
| Username | kali |
| Password | kali123 |
| SSH | ssh kali@192.168.56.20 |
| Attack Script | ~/kali_attack.sh 192.168.56.10 |
| Custom Scanner | python3 ~/kali_custom_scanner.py 192.168.56.10 |

### VMware Network

| Item | Value |
|------|-------|
| Network | VMnet8 NAT |
| Subnet | 192.168.56.0/24 |
| Gateway | 192.168.56.2 |
| Ubuntu | 192.168.56.10 |
| Kali | 192.168.56.20 |
| Host | 192.168.56.1 |

---

*Document prepared by Anas Moulay - ENSA Kenitra, AI Module S2 2026*
