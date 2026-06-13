import os
import pandas as pd
import numpy as np
import joblib
from config import FEATURES as features

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)

from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

print("====================================")
print("1. LOADING PREPROCESSED DATASET")
print("====================================")

# Load the preprocessed dataset if available, otherwise fallback to raw
try:
    df = pd.read_csv("../data/preprocessed.csv")
    print("Loaded preprocessed.csv")
except FileNotFoundError:
    print("Warning: preprocessed.csv not found. Loading raw dataset...")
    df = pd.read_csv("../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    df.columns = [col.strip() for col in df.columns]

print("====================================")
print("2. FEATURES")
print("====================================")

X = df[features].copy()

# Add placeholders for live integration
X['shadow_node_interaction'] = 0
X['mtd_port_delta'] = 0

# Nettoyage
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median())

# Labels
y = df['Label'].apply(lambda x: 1 if str(x).strip() == "PortScan" else 0)

print(f"Dataset shape: {X.shape}")

print("====================================")
print("3. TRAIN / TEST SPLIT & PREPROCESSING")
print("====================================")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"Train size: {X_train.shape[0]}, Test size: {X_test.shape[0]}")

# StandardScaler - Fit on train, transform on both
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

os.makedirs("../models", exist_ok=True)
joblib.dump(scaler, "../models/scaler.pkl")
print("StandardScaler saved to ../models/scaler.pkl")

# SMOTE
print("\nApplying SMOTE...")
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
print(f"Train size after SMOTE: {X_train_res.shape[0]}")

# CV setup
cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)

print("====================================")
print("4. RANDOM FOREST")
print("====================================")

rf = RandomForestClassifier(n_estimators=100, random_state=42)
print("Running 10-Fold CV for RF...")
rf_cv_scores = cross_val_score(rf, X_train_res, y_train_res, cv=cv, scoring='f1', n_jobs=-1)
print(f"RF CV F1 Score: {rf_cv_scores.mean():.4f} (+/- {rf_cv_scores.std() * 2:.4f})")

rf.fit(X_train_res, y_train_res)
joblib.dump(rf, "../models/random_forest.pkl")

print("====================================")
print("5. XGBOOST")
print("====================================")

xgb = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    eval_metric="logloss"
)
print("Running 10-Fold CV for XGBoost...")
xgb_cv_scores = cross_val_score(xgb, X_train_res, y_train_res, cv=cv, scoring='f1', n_jobs=-1)
print(f"XGB CV F1 Score: {xgb_cv_scores.mean():.4f} (+/- {xgb_cv_scores.std() * 2:.4f})")

xgb.fit(X_train_res, y_train_res)
joblib.dump(xgb, "../models/xgboost.pkl")

print("====================================")
print("6. ISOLATION FOREST")
print("====================================")

iso = IsolationForest(
    contamination='auto',
    random_state=42
)
iso.fit(X_train_scaled)
joblib.dump(iso, "../models/isolation_forest.pkl")

print("\nModels successfully trained and saved.")