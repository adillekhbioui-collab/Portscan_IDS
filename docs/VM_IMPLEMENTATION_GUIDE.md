# AEGIS VM Implementation Guide

**Author:** Anas Moulay
**Topology:** Kali Linux (Attaquant) <--- lab-cyber ---> Ubuntu Victime (AEGIS)

---

## Quick Reference

| Item | Value |
|------|-------|
| Network | lab-cyber (VirtualBox Internal Network) |
| Subnet | 192.168.100.0/24 |
| Ubuntu Victime IP | 192.168.100.20/24 |
| Kali Linux IP | 192.168.100.10/24 |
| Dashboard | http://192.168.100.20:5000 |
| SSH Ubuntu | ssh aegis@192.168.100.20 |
| SSH Kali | ssh kali@192.168.100.10 |

---

## Part 1: Network Topology

```
Kali Linux (Attaquant)
  eth1: 192.168.100.10/24
        |
        | VirtualBox Internal Network: lab-cyber
        |
Ubuntu Victime (AEGIS)
  enp0s8: 192.168.100.20/24
```

### VirtualBox Network Setup

1. Open VirtualBox > File > Host Network Manager
2. Create a **Host-Only Network** named `lab-cyber`
3. Set IPv4: `192.168.100.1/24`, DHCP Server: **Disabled**
4. Both VMs use **Adapter 2** attached to `lab-cyber` (Internal Network)

---

## Part 2: Ubuntu Victime Setup (192.168.100.20)

### Step 2.1: Install Ubuntu Server

- Install Ubuntu Server 22.04 LTS in VirtualBox
- VM name: `Ubuntu Victime`
- RAM: 4GB, CPU: 2 cores, Disk: 40GB
- Adapter 1: NAT (for internet access, enp0s3)
- Adapter 2: Internal Network `lab-cyber` (enp0s8)

### Step 2.2: Configure Static IP

```bash
sudo nmcli con mod "Wired connection 1" ipv4.addresses "192.168.100.20/24"
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"
```

### Step 2.3: Verify Connectivity

```bash
ip addr show enp0s8          # Should show: 192.168.100.20/24
ping -c 3 192.168.100.10    # Should reach Kali
```

### Step 2.4: Install Dependencies

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nmap ufw libnetfilter-queue-dev nftables
```

### Step 2.5: Clone and Setup AEGIS

```bash
cd /home/$USER
git clone https://github.com/MrGray17/Portscan_IDS.git AEGIS
cd AEGIS
python3 -m venv venv
source venv/bin/activate
pip install flask flask-socketio scapy joblib xgboost scikit-learn pandas numpy
```

### Step 2.6: Configure Firewall

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.100.0/24
sudo ufw allow from 192.168.100.0/24 to any port 5000
sudo ufw --force enable
```

### Step 2.7: Verify Models

```bash
source venv/bin/activate
python3 -c "import joblib; rf = joblib.load("models/saved/rf_model.pkl"); print(f"RF: {rf.n_features_in_} features")"
# Should show: 11 features
```

### Step 2.8: Start AEGIS Dashboard

```bash
cd /home/$USER/AEGIS && source venv/bin/activate
python dashboard/app.py
```

Dashboard will be at: **http://192.168.100.20:5000**

---

## Part 3: Kali Linux Setup (192.168.100.10)

### Step 3.1: Install Kali Linux

- Install Kali Linux 2026.1 in VirtualBox
- VM name: `kali-linux-2026.1-virtualbox-amd64`
- RAM: 4GB, CPU: 2 cores, Disk: 40GB
- Adapter 1: NAT (for internet, eth0)
- Adapter 2: Internal Network `lab-cyber` (eth1)

### Step 3.2: Configure Static IP

```bash
sudo ip addr add 192.168.100.10/24 dev eth1
sudo ip link set eth1 up
```

### Step 3.3: Verify Connectivity

```bash
ip addr show eth1           # Should show: 192.168.100.10/24
ping -c 3 192.168.100.20    # Should reach Ubuntu
```

### Step 3.4: Copy Attack Scripts

```bash
scp demo/* kali@192.168.100.10:~/
```

### Step 3.5: Run Attack Simulation

```bash
chmod ~/kali_attack.sh
~/kali_attack.sh 192.168.100.20
```

### Step 3.6: Custom Low-Rate Scanner

```bash
python3 ~/kali_custom_scanner.py 192.168.100.20
```

---

## Part 4: Running the Demo

### Step 4.1: Start Ubuntu Server (Defense)

```bash
ssh aegis@192.168.100.20
cd /home/aegis/AEGIS && source venv/bin/activate
python dashboard/app.py &
```

Open dashboard: **http://192.168.100.20:5000**

### Step 4.2: Run the Attack (Kali)

```bash
ssh kali@192.168.100.10
~/kali_attack.sh 192.168.100.20
```

### What Happens During the Demo

```
Phase 1: Fast SYN scan (1000 ports)
  Rapid SYN packets flood Ubuntu
  ML model classifies as ATTACK
  Dashboard: attacks counter increases
  Threat level: LOW -> MEDIUM -> HIGH

Phase 2: Service version scan
  Targeted probes detected and logged

Phase 3: Slow stealth scan (60s)
  Low-rate scanner tests Isolation Forest

Phase 4: OS detection
  Nmap fingerprinting flagged as recon

Phase 5: UDP scan
  Different protocol detected as anomaly
```

### Step 4.3: Observe Dashboard

| What You See               | What It Meaning                              |
|---------------------------|--------------------------------------------|
| DETECTED counter increases | ML models classifying attack traffic       |
| Threat Level changes color | LOW (green) -> MEDIUM (yellow) -> HIGH (red) |
| DETECTION LOG fills rows   | Each row = one classified network flow     |
| VERDICT shows ATTACK       | ML model flagged this as malicious          |
| ACTION shows BLOCK         | System auto-blocked the source IP           |
| DECEPTION LOG shows REDIRECT | Attacker redirected to honeypot           |

---

## Part 5: Network Diagram

```
+------------------+         +------------------+
|   Kali Linux     |         |  Ubuntu Victime  |
|  (Attaquant)     |         |     (AEGIS)      |
|                  |         |                  |
| eth1:            |         | enp0s8:          |
| 192.168.100.10/24|         | 192.168.100.20/24|
+--------+---------+         +---------+--------+
         |                             |
         |   lab-cyber (Internal Net)  |
         |   192.168.100.0/24          |
         +-----------------------------+
```

Attack Flow:
```
Kali (192.168.100.10) --[Nmap/Custom Scanner]--> Ubuntu (192.168.100.20)
                                              Scapy capture on enp0s8
                                              ML classification
                                              Dashboard update
```

---

## Part 6: Troubleshooting

| Problem | Solution |
|---------|----------|
| Cannot ping between VMs | Check both adapters, verify lab-cyber network, run `sudo nmcli con up''
| Dashboard not accessible | Ensure port 5000 is open: `sudo ufw allow 5000` |
| No detection events | Verify models exist: `ls models/saved/` |
| Port 5000 already in use | Kill existing: `sudo fuser -k 5000/tcp` |
| nftables errors | Install: `sudo apt install nftables` |
| NetfilterQueue errors | Install: `sudo apt install libnetfilter-queue-dev` |

---

## Part 7: Quick Reference

| Command | Location | Description |
|---------|----------|-------------|
| `python dashboard/app.py` | Ubuntu | Start dashboard |
| `~/kali_attack.sh 192.168.100.20` | Kali | Run attack simulation |
| `python3 ~/kali_custom_scanner.py 192.168.100.20` | Kali | Low-rate scanner |
| `http://192.168.100.20:5000` | Browser | Dashboard URL |
| `ssh aegis@192.168.100.20` | Host | SSH to Ubuntu |
| `ssh kali@192.168.100.10` | Host | SSH to Kali |
| `ip addr show enp0s8` | Ubuntu | Check IP |
| `ip addr show eth1` | Kali | Check IP |

