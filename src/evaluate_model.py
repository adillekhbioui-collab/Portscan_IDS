import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

# =====================================================
# 1. CHARGEMENT DU DATASET
# =====================================================

df = pd.read_csv(
    "../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

# =====================================================
# 2. FEATURES SELECTIONNEES
# =====================================================

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

# =====================================================
# 3. NETTOYAGE
# =====================================================

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# =====================================================
# 4. LABELS
# =====================================================

y = df[' Label'].apply(
    lambda x: 1 if x.strip() == "PortScan" else 0
)

# =====================================================
# 5. TRAIN / TEST SPLIT
# =====================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# =====================================================
# FONCTION D'EVALUATION
# =====================================================

results = []

def evaluate_model(name, y_true, y_pred):

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )
    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )
    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    results.append([
        name,
        round(accuracy, 4),
        round(precision, 4),
        round(recall, 4),
        round(f1, 4)
    ])

    print("\n")
    print("=" * 50)
    print(name)
    print("=" * 50)

    print("Accuracy  :", round(accuracy, 4))
    print("Precision :", round(precision, 4))
    print("Recall    :", round(recall, 4))
    print("F1 Score  :", round(f1, 4))


# =====================================================
# 6. RANDOM FOREST
# =====================================================

rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

rf.fit(X_train, y_train)

rf_pred = rf.predict(X_test)

evaluate_model(
    "Random Forest",
    y_test,
    rf_pred
)

# Confusion Matrix RF

cm_rf = confusion_matrix(y_test, rf_pred)

plt.figure(figsize=(6, 4))
sns.heatmap(
    cm_rf,
    annot=True,
    fmt='d'
)

plt.title("Random Forest Confusion Matrix")

plt.savefig(
    "../results/confusion_matrix_rf.png"
)

plt.close()

# =====================================================
# 7. XGBOOST
# =====================================================

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
    "XGBoost",
    y_test,
    xgb_pred
)

# Confusion Matrix XGB

cm_xgb = confusion_matrix(y_test, xgb_pred)

plt.figure(figsize=(6, 4))
sns.heatmap(
    cm_xgb,
    annot=True,
    fmt='d'
)

plt.title("XGBoost Confusion Matrix")

plt.savefig(
    "../results/confusion_matrix_xgb.png"
)

plt.close()

# =====================================================
# 8. ISOLATION FOREST
# =====================================================

iso = IsolationForest(
    contamination=0.1,
    random_state=42
)

iso.fit(X_train)

iso_pred = iso.predict(X_test)

# Conversion :
# -1 = anomalie = PortScan
#  1 = normal = BENIGN

iso_pred = np.where(
    iso_pred == -1,
    1,
    0
)

evaluate_model(
    "Isolation Forest",
    y_test,
    iso_pred
)

# Confusion Matrix ISO

cm_iso = confusion_matrix(y_test, iso_pred)

plt.figure(figsize=(6, 4))
sns.heatmap(
    cm_iso,
    annot=True,
    fmt='d'
)

plt.title("Isolation Forest Confusion Matrix")

plt.savefig(
    "../results/confusion_matrix_iso.png"
)

plt.close()

# =====================================================
# 9. EXPORT DES METRIQUES
# =====================================================

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

results_df.to_csv(
    "../results/metrics.csv",
    index=False
)

print("\n")
print("=" * 60)
print("RESULTATS SAUVEGARDES")
print("=" * 60)

print(
    "\nDossier results :"
)

print(
    "- confusion_matrix_rf.png"
)
print(
    "- confusion_matrix_xgb.png"
)
print(
    "- confusion_matrix_iso.png"
)
print(
    "- metrics.csv"
)