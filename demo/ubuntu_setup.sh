#!/bin/bash
# =============================================================
# AEGIS — Ubuntu Server Setup Script
# Run this on your Ubuntu Server VM to install and launch AEGIS
# =============================================================
set -e

echo "============================================="
echo "  AEGIS — Network IDS + MTD Setup"
echo "  Ubuntu Server VM"
echo "============================================="

# --- 1. System Dependencies ---
echo ""
echo "[1/8] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv \
    git curl net-tools iptables-persistent build-essential libnetfilter-queue-dev

# --- 2. Clone the Repository ---
echo ""
echo "[2/8] Cloning AEGIS repository..."
REPO_DIR="$HOME/AEGIS-Portscan_IDS"
if [ -d "$REPO_DIR" ]; then
    echo "  Repository already exists at $REPO_DIR, pulling latest..."
    cd "$REPO_DIR" && git pull
else
    git clone https://github.com/MrGray17/Portscan_IDS.git "$REPO_DIR"
fi
cd "$REPO_DIR"

# --- 3. Python Virtual Environment ---
echo ""
echo "[3/8] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# --- 4. Python Dependencies ---
echo ""
echo "[4/8] Installing Python packages..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
pip install scikit-learn xgboost imbalanced-learn joblib -q

# --- 5. Create Required Directories ---
echo ""
echo "[5/8] Creating data and model directories..."
mkdir -p data models/saved detection/pipeline_output

# --- 6. Run ML Training Pipeline ---
echo ""
echo "[6/8] Training detection models (this takes 2-5 minutes)..."
echo "  Loading CICIDS2017 PortScan dataset..."
echo "  Training Random Forest + XGBoost + Isolation Forest..."

# Check if models already exist
if [ -f "models/saved/rf_model.pkl" ] && [ -f "models/saved/xgb_model.pkl" ]; then
    echo "  Trained models found — skipping training. Delete models/saved/ to retrain."
else
    python3 detection/src/retrain_11features.py 2>&1 | tail -20
    echo "  Training complete."
fi

# --- 7. Configure Firewall Rules ---
echo ""
echo "[7/8] Configuring iptables for deception subsystem..."
echo "  NOTE: You'll need to run the NFQUEUE rule manually (requires sudo):"
echo "  sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1"

# --- 8. Launch Services ---
echo ""
echo "[8/8] Launching AEGIS services..."

# Launch dashboard in background
echo "  Starting dashboard on port 5000..."
nohup python3 dashboard/app.py > data/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "  Dashboard PID: $DASHBOARD_PID"

# --- Status ---
echo ""
echo "============================================="
echo "  AEGIS is now running!"
echo "============================================="
echo ""
echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):5000"
echo "  Dashboard PID: $DASHBOARD_PID"
echo ""
echo "  To stop: kill $DASHBOARD_PID"
echo ""
echo "  Offline demo (run on saved Nmap XMLs):"
echo "    python3 bridge/nmap_parser.py --scans-dir capture/azerty/scans --output nmap_features.csv"
echo "    python3 bridge/bridge.py --input nmap_features.csv"
echo ""
echo "  Live demo (requires 2-VM setup):"
echo "    1. Open the dashboard URL in your browser"
echo "    2. Start your Kali VM and run: bash demo/kali_attack.sh"
echo "    3. Watch events appear in real-time on the dashboard"
