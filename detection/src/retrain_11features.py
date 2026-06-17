#!/usr/bin/env python3
"""Retrain models with 11 features (9 CSV + 2 placeholders)."""
import warnings
warnings.filterwarnings("ignore")
import os, sys, json, time, numpy as np, pandas as pd, joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

BASE = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE / "data"
MODELS_DIR = BASE / "models" / "saved"
RAW_DIR = BASE / "capture" / "raw_datasets"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = RAW_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Flow IAT Mean",
    "Bwd Packet Length Mean",
    "Init_Win_bytes_forward",
]

def fetch_dataset():
    if CSV_PATH.exists():
        print(f"[1/8] Dataset found: {CSV_PATH}")
        return
    print("[1/8] Downloading CICIDS2017 PortScan dataset...")
    import gdown
    gdown.download(url="https://drive.google.com/uc?id=1aFPfPEhV7G0jFJ9mLk7rQ4KJQ1q8Q6mD", output=str(CSV_PATH), quiet=False)

def load_and_clean():
    print("[2/8] Loading and cleaning data...")
    df = pd.read_csv(CSV_PATH)
    print(f"  Raw shape: {df.shape}")
    df.columns = [col.strip() for col in df.columns]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    label_col = [c for c in df.columns if c.lower() == "label"][0]
    df[label_col] = df[label_col].apply(lambda x: 1 if "portscan" in str(x).lower() else 0)
    available = [f for f in FEATURES if f in df.columns]
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        print(f"  WARNING: Missing features: {missing}")
    df[available] = df[available].fillna(df[available].median())
    return df, available, label_col

def outlier_removal(df, features):
    print("[3/8] Outlier detection (IQR) + capping...")
    for col in features:
        Q1, Q3 = df[col].quantile(0.25), df[col].quantile(0.75)
        IQR = Q3 - Q1
        if IQR == 0:
            print(f"  {col}: Skipping IQR capping (Q1=Q3={Q1}, zero variance)")
            continue
        df[col] = df[col].clip(Q1 - 1.5 * IQR, Q3 + 1.5 * IQR)
    return df

def skewness_correction(df, features):
    print("[4/8] Skewness correction (log1p)...")
    for col in features:
        if abs(df[col].skew()) > 1.0:
            min_val = df[col].min()
            if min_val < 0:
                df[col] = df[col] - min_val
            df[col] = np.log1p(df[col])
    return df

def add_placeholders(df):
    print("[5/8] Adding MTD placeholder columns...")
    df["shadow_node_interaction"] = 0.0
    df["mtd_port_delta"] = 0.0
    return df

def split_and_balance(X, y):
    print("[6/8] Train/test split + SMOTE...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"  Train: {len(X_train)} | Test: {len(X_test)}")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
    print(f"  After SMOTE: {len(X_train_res)}")
    return X_train_res, X_test_scaled, y_train_res, y_test, scaler

def train_models(X_train, y_train, X_train_unscaled):
    print("[7/8] Training models...")
    print("  Training Random Forest...")
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    print(f"    Done in {time.time()-t0:.1f}s")
    print("  Training XGBoost...")
    t0 = time.time()
    xgb = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42, eval_metric="logloss")
    xgb.fit(X_train, y_train)
    print(f"    Done in {time.time()-t0:.1f}s")
    print("  Training Isolation Forest (unsupervised)...")
    t0 = time.time()
    iso = IsolationForest(contamination="auto", random_state=42)
    iso.fit(X_train_unscaled)
    print(f"    Done in {time.time()-t0:.1f}s")
    return rf, xgb, iso

def evaluate(model, X_test, y_test, name, unsupervised=False):
    if unsupervised:
        y_pred = np.where(model.predict(X_test) == -1, 1, 0)
        y_prob = None
    else:
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    acc = accuracy_score(y_test, y_pred) * 100
    prec = precision_score(y_test, y_pred) * 100
    rec = recall_score(y_test, y_pred) * 100
    f1 = f1_score(y_test, y_pred) * 100
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
    auc = roc_auc_score(y_test, y_prob) if y_prob is not None else 0.0
    print(f"\n  === {name} ===")
    print(f"  TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"  Accuracy:  {acc:.3f}%")
    print(f"  Precision: {prec:.3f}%")
    print(f"  Recall:    {rec:.3f}%")
    print(f"  F1:        {f1:.3f}%")
    print(f"  FPR:       {fpr:.4f}%")
    print(f"  AUC-ROC:   {auc:.6f}")
    return {"model": name, "accuracy": acc, "precision": prec, "recall": rec, "f1_score": f1, "fpr": fpr, "auc_roc": auc, "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn)}

def save_artifacts(rf, xgb, iso, scaler, feature_names, all_metrics):
    print("\n[8/8] Saving artifacts...")
    joblib.dump(rf, MODELS_DIR / "rf_model.pkl")
    joblib.dump(xgb, MODELS_DIR / "xgb_model.pkl")
    joblib.dump(iso, MODELS_DIR / "isolation_forest.pkl")
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    with open(MODELS_DIR / "feature_columns.json", "w") as f:
        json.dump(feature_names, f, indent=2)
    with open(MODELS_DIR / "evaluation_metrics.json", "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"  Models saved to {MODELS_DIR}/")
    print(f"  Features: {len(feature_names)} ({feature_names})")

if __name__ == "__main__":
    print("=" * 60)
    print("AEGIS - Retraining with 11 features (Adil's config)")
    print("=" * 60)
    fetch_dataset()
    df, available, label_col = load_and_clean()
    df = outlier_removal(df, available)
    df = skewness_correction(df, available)
    df = add_placeholders(df)
    all_features = available + ["shadow_node_interaction", "mtd_port_delta"]
    print(f"  Final features: {len(all_features)} -> {all_features}")
    X = df[all_features].copy()
    y = df[label_col]
    X_train_res, X_test_scaled, y_train_res, y_test, scaler = split_and_balance(X, y)
    X_train_unscaled = X_train_res
    rf, xgb, iso = train_models(X_train_res, y_train_res, X_train_unscaled)
    all_metrics = []
    all_metrics.append(evaluate(rf, X_test_scaled, y_test, "Random Forest"))
    all_metrics.append(evaluate(xgb, X_test_scaled, y_test, "XGBoost"))
    all_metrics.append(evaluate(iso, X_test_scaled, y_test, "Isolation Forest", unsupervised=True))
    save_artifacts(rf, xgb, iso, scaler, all_features, all_metrics)
    print("\n" + "=" * 60)
    print("DONE - All models retrained with 11 features")
    print("=" * 60)
