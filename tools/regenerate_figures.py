"""Regenerate all figures using retrained models for ch04/ch05."""
import warnings
warnings.filterwarnings("ignore")
import os, numpy as np, pandas as pd, joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import confusion_matrix, roc_curve, roc_auc_score

BASE = Path(r"C:\Users\Adill\Documents\Ci_RST_S2\AI\New folder\mini_projet\Portscan_IDS")
OUT_DIR = BASE / "docs" / "reports" / "05_final" / "figures" / "data"
MODELS_DIR = BASE / "models" / "saved"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Load retrained models
rf = joblib.load(MODELS_DIR / "rf_model.pkl")
xgb = joblib.load(MODELS_DIR / "xgb_model.pkl")
iso = joblib.load(MODELS_DIR / "isolation_forest.pkl")
scaler = joblib.load(MODELS_DIR / "scaler.pkl")

# Load dataset for test split
CSV = BASE / "capture" / "raw_datasets" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
df = pd.read_csv(CSV)
df.columns = [c.strip() for c in df.columns]

FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "SYN Flag Count", "RST Flag Count", "ACK Flag Count",
    "Flow IAT Mean", "Bwd Packet Length Mean", "Init_Win_bytes_forward",
]
X = df[FEATURES].copy()
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X = X.fillna(X.median())
X["shadow_node_interaction"] = 0.0
X["mtd_port_delta"] = 0.0

label_col = [c for c in df.columns if c.lower() == "label"][0]
y = df[label_col].apply(lambda x: 1 if "portscan" in str(x).lower() else 0)

from sklearn.model_selection import train_test_split
_, X_test, _, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_test_scaled = scaler.transform(X_test)

models = {
    "Random Forest": (rf, False),
    "XGBoost": (xgb, False),
    "Isolation Forest": (iso, True),
}

# Regenerate confusion matrices
for name, (model, unsupervised) in models.items():
    if unsupervised:
        y_pred = np.where(model.predict(X_test_scaled) == -1, 1, 0)
    else:
        y_pred = model.predict(X_test_scaled)
    cm = confusion_matrix(y_test, y_pred)
    fname = f"confusion_matrix_{name.replace(' ', '_').lower()}.png"
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['BENIGN', 'PORT_SCAN'],
                yticklabels=['BENIGN', 'PORT_SCAN'])
    plt.title(f'{name} — Confusion Matrix', fontsize=13, fontweight='bold')
    plt.xlabel('Predicted', fontsize=11)
    plt.ylabel('Actual', fontsize=11)
    plt.tight_layout()
    plt.savefig(OUT_DIR / fname, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  Saved {fname}")

# Regenerate ROC curves for supervised models
for name, (model, unsupervised) in models.items():
    if unsupervised:
        continue
    y_prob = model.predict_proba(X_test_scaled)[:, 1]
    auc = roc_auc_score(y_test, y_prob)
    fname = f"roc_{name.replace(' ', '_').lower()}.png"
    fpr_vals, tpr_vals, _ = roc_curve(y_test, y_prob)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr_vals, tpr_vals, linewidth=2, label=f'{name} (AUC = {auc:.4f})')
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
    plt.xlabel('False Positive Rate', fontsize=11)
    plt.ylabel('True Positive Rate', fontsize=11)
    plt.title(f'{name} — ROC Curve', fontsize=13, fontweight='bold')
    plt.legend(fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / fname, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  Saved {fname}")

print("\nDone — all figures regenerated from retrained models.")
