import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier


# ====================================
# 1. CHARGEMENT DU DATASET
# ====================================

df = pd.read_csv(
    "../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

# ====================================
# 2. FEATURES
# ====================================

features = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' SYN Flag Count',
    ' RST Flag Count',
    ' ACK Flag Count',
    ' Flow IAT Mean',
    ' Bwd Packet Length Mean'
]

X = df[features]

# Nettoyage
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# Labels
y = df[' Label'].apply(
    lambda x: 1 if x.strip() == "PortScan" else 0
)

# ====================================
# 3. TRAIN / TEST SPLIT
# ====================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ====================================
# FONCTION D'EVALUATION
# ====================================

def evaluate_model(name, y_true, y_pred):

    print("\n" + "="*50)
    print(name)
    print("="*50)

    print("Accuracy  :", round(accuracy_score(y_true, y_pred), 4))
    print("Precision :", round(precision_score(y_true, y_pred, zero_division=0), 4))
    print("Recall    :", round(recall_score(y_true, y_pred, zero_division=0), 4))
    print("F1 Score  :", round(f1_score(y_true, y_pred, zero_division=0), 4))

    try:
        print("AUC ROC   :", round(roc_auc_score(y_true, y_pred), 4))
    except:
        print("AUC ROC   : Non calculable")


# ====================================
# 4. RANDOM FOREST
# ====================================

rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

rf.fit(X_train, y_train)

rf_pred = rf.predict(X_test)

evaluate_model(
    "RANDOM FOREST",
    y_test,
    rf_pred
)

# ====================================
# 5. XGBOOST
# ====================================

xgb = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    eval_metric="logloss"
)

xgb.fit(X_train, y_train)

xgb_pred = xgb.predict(X_test)

evaluate_model(
    "XGBOOST",
    y_test,
    xgb_pred
)

# ====================================
# 6. ISOLATION FOREST
# ====================================

iso = IsolationForest(
    contamination=0.1,
    random_state=42
)

iso.fit(X_train)

iso_pred = iso.predict(X_test)

# Conversion :
# -1 = anomalie (PortScan)
#  1 = normal (BENIGN)

iso_pred = np.where(iso_pred == -1, 1, 0)

evaluate_model(
    "ISOLATION FOREST",
    y_test,
    iso_pred
)

# ====================================
# 7. TABLEAU FINAL
# ====================================

results = []

models = {
    "Random Forest": rf_pred,
    "XGBoost": xgb_pred,
    "Isolation Forest": iso_pred
}

for name, pred in models.items():

    results.append([
        name,
        round(accuracy_score(y_test, pred), 4),
        round(precision_score(y_test, pred, zero_division=0), 4),
        round(recall_score(y_test, pred, zero_division=0), 4),
        round(f1_score(y_test, pred, zero_division=0), 4)
    ])

print("\n")
print("="*70)
print("COMPARAISON DES MODELES")
print("="*70)

results_df = pd.DataFrame(
    results,
    columns=[
        "Model",
        "Accuracy",
        "Precision",
        "Recall",
        "F1 Score"
    ]
)

print(results_df)
import joblib

# Sauvegarde Random Forest
joblib.dump(
    rf,
    "../models/random_forest.pkl"
)

# Sauvegarde XGBoost
joblib.dump(
    xgb,
    "../models/xgboost.pkl"
)

# Sauvegarde Isolation Forest
joblib.dump(
    iso,
    "../models/isolation_forest.pkl"
)

print("Modèles sauvegardés.")