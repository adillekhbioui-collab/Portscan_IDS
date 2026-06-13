import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from config import FEATURES as features

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    roc_auc_score
)

print("=====================================================")
print("1. LOADING DATA & MODELS")
print("=====================================================")

try:
    df = pd.read_csv("../data/preprocessed.csv")
except FileNotFoundError:
    df = pd.read_csv("../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    df.columns = [col.strip() for col in df.columns]

X = df[features].copy()
X['shadow_node_interaction'] = 0
X['mtd_port_delta'] = 0

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median())

y = df['Label'].apply(lambda x: 1 if str(x).strip() == "PortScan" else 0)

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Load Models
scaler = joblib.load("../models/scaler.pkl")
rf = joblib.load("../models/random_forest.pkl")
xgb = joblib.load("../models/xgboost.pkl")
iso = joblib.load("../models/isolation_forest.pkl")

X_test_scaled = scaler.transform(X_test)

os.makedirs("../results", exist_ok=True)
results = []

def evaluate_and_verify(name, model, X_test_data, y_true):
    print("\n" + "=" * 60)
    print(f"EVALUATING: {name}")
    print("=" * 60)
    
    y_pred = model.predict(X_test_data)
    
    # ISO Forest conversion
    if name == "Isolation Forest":
        y_pred = np.where(y_pred == -1, 1, 0)
        
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Confusion Matrix & FPR
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    # AUC-ROC
    auc = "N/A"
    try:
        if name != "Isolation Forest":
            y_probs = model.predict_proba(X_test_data)[:, 1]
            auc = roc_auc_score(y_true, y_probs)
            
            # Save ROC Curve
            fpr_roc, tpr_roc, _ = roc_curve(y_true, y_probs)
            plt.figure(figsize=(6, 4))
            plt.plot(fpr_roc, tpr_roc, label=f'{name} (AUC = {auc:.4f})')
            plt.plot([0, 1], [0, 1], 'k--')
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'{name} ROC Curve')
            plt.legend()
            plt.tight_layout()
            plt.savefig(f"../results/roc_{name.replace(' ', '_').lower()}.png")
            plt.close()
    except Exception as e:
        print(f"AUC calculation failed: {e}")

    results.append([
        name,
        round(accuracy, 4),
        round(precision, 4),
        round(recall, 4),
        round(f1, 4),
        round(auc, 4) if isinstance(auc, float) else auc,
        round(fpr, 4)
    ])
    
    # Print Classification Report
    print(classification_report(y_true, y_pred, target_names=['BENIGN', 'PortScan']))
    
    print("\n--- SUCCESS CRITERIA VERIFICATION ---")
    print(f"F1-Score (>= 88%) : {f1*100:.2f}% -> {'[PASS]' if f1 >= 0.88 else '[FAIL]'}")
    print(f"Accuracy (>= 90%) : {accuracy*100:.2f}% -> {'[PASS]' if accuracy >= 0.90 else '[FAIL]'}")
    print(f"FPR (< 6%)       : {fpr*100:.2f}% -> {'[PASS]' if fpr < 0.06 else '[FAIL]'}")
    
    # Save Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title(f"{name} Confusion Matrix")
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig(f"../results/confusion_matrix_{name.replace(' ', '_').lower()}.png")
    plt.close()

# Evaluate Models
evaluate_and_verify("Random Forest", rf, X_test_scaled, y_test)
evaluate_and_verify("XGBoost", xgb, X_test_scaled, y_test)
evaluate_and_verify("Isolation Forest", iso, X_test_scaled, y_test)

# Export Metrics
results_df = pd.DataFrame(
    results,
    columns=["Model", "Accuracy", "Precision", "Recall", "F1 Score", "AUC-ROC", "FPR"]
)
results_df.to_csv("../results/metrics.csv", index=False)

print("\n" + "=" * 60)
print("FINAL METRICS COMPARISON")
print("=" * 60)
print(results_df)
print("\nResults and plots saved to ../results/")