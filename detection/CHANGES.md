# CHANGES.md — What Was Modified and Why

> **Who made these changes:** Adill (on behalf of the AEGIS Entropy team)  
> **When:** June 2026  
> **Purpose:** Refactor the ML pipeline to meet the professor's academic standards and the project's official Data Dictionary requirements.

---

## Quick Summary

| File | Type of Change | Why |
|---|---|---|
| `src/data_preprocessing.py` | **Full rewrite** | Missing outlier detection, log transform, and visualizations |
| `src/modeltrain.py` | **Full rewrite** | Missing StandardScaler, SMOTE, K-Fold CV — caused data leakage |
| `src/evaluate_model.py` | **Full rewrite** | Missing AUC-ROC, FPR, classification report, success criteria check |
| `src/predict.py` | **Updated** | Needed to load new scaler and use updated feature list |
| `src/feature_selection.py` | **Updated** | Feature list was outdated, didn't match Data Dictionary |
| `requirements.txt` | **1 line added** | `imbalanced-learn` was missing (needed for SMOTE) |
| `report/` | **New folder** | LaTeX report + all figures for the academic deliverable |

---

## File-by-File Breakdown

---

### 1. `src/data_preprocessing.py` — Full Rewrite

**The original script** loaded the data and did basic cleaning (removed NaN, generated a correlation heatmap). That was it.

**What was missing:**
- No outlier detection at all
- No skewness analysis
- No log transformation for highly skewed features
- No class distribution visualization
- Column names with leading spaces were not stripped, causing silent errors

**What was added:**

#### Step 1 — Column name stripping
```python
df.columns = [col.strip() for col in df.columns]
```
The CICIDS2017 CSV has spaces before column names (e.g. `' Flow Duration'`). Without stripping, accessing any column by name silently fails or raises a KeyError.

#### Step 2 — Replace infinities with NaN, then fill with median
```python
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df[FEATURES] = df[FEATURES].fillna(df[FEATURES].median())
```
Some flow-level calculations (like packet rate) produce `inf` when duration is zero. These must be handled before any processing. Median was chosen over mean because it is robust to extreme values.

#### Step 3 — Class distribution bar chart (new)
```python
df["Label"].value_counts().plot(kind="bar")
plt.savefig("../results/class_distribution.png")
```
Saved to `results/class_distribution.png`. Used in the report.

#### Step 4 — Outlier detection using IQR (new)
```python
Q1 = df[feature].quantile(0.25)
Q3 = df[feature].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
```
For each of the 9 features, IQR bounds are computed and outlier counts are printed. Instead of **deleting** rows (which would remove attack samples), outliers are **capped** (Winsorization) — values above the upper bound are set to the upper bound, and vice versa.

A boxplot is saved for each feature to `results/boxplot_<FeatureName>.png`.

#### Step 5 — Skewness check and log transform (new)
```python
if abs(df[feature].skew()) > 1.0:
    df[feature] = np.log1p(df[feature])
```
Features with a skewness coefficient above 1.0 are log-transformed using `np.log1p` (which handles zero values safely). This normalizes the distribution and improves model convergence.

#### Step 6 — Export preprocessed data
```python
df.to_csv("../data/preprocessed.csv", index=False)
```
The cleaned dataset is saved so the training script always works on clean data without re-running preprocessing.

---

### 2. `src/modeltrain.py` — Full Rewrite

**The original script** loaded data, did a basic train/test split, and trained the three models. No scaling, no balancing, no cross-validation.

**What was missing and why it mattered:**

| Problem | Consequence |
|---|---|
| No `StandardScaler` | Distance-based operations (and gradient models) are biased when features have different scales |
| No SMOTE | Slight class imbalance (55/45) could bias training toward the majority class |
| No K-Fold CV | A single train/test split gives unreliable performance estimates |
| Isolation Forest `contamination=0.1` hardcoded | Wrong — the actual attack rate in the dataset is ~55%, not 10% |
| No scaler saved | `predict.py` had no way to apply the same scaling at inference time |

**What was changed:**

#### Feature list — aligned to Data Dictionary
The 9 features used are directly mapped from the project's official Data Dictionary. Two additional placeholder columns (`shadow_node_interaction = 0`, `mtd_port_delta = 0`) are added to maintain the full 11-feature input schema for future integration with the honeypot and MTD modules.

#### StandardScaler — fit on train only
```python
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)  # Fit here
X_test_scaled  = scaler.transform(X_test)        # Apply only
joblib.dump(scaler, "../models/scaler.pkl")      # Save for predict.py
```
> **Important:** The scaler is fitted **only on the training set**. If it were fitted on the full dataset before splitting, the test set statistics would leak into the training process — this is called **data leakage** and it falsely inflates evaluation scores.

#### SMOTE — applied after splitting and scaling, on train only
```python
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
```
SMOTE generates synthetic samples of the minority class. It is applied **after** splitting and **after** scaling — never before, to avoid leakage.

#### Stratified K-Fold Cross-Validation (10 folds)
```python
cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
scores = cross_val_score(model, X_train_res, y_train_res, cv=cv, scoring='f1')
```
Runs 10 rounds of training/validation, each on a different subset of the data. The stratified option ensures each fold has the same class ratio. Results (mean F1 ± std) are printed before final training.

#### Isolation Forest — fixed contamination
```python
iso = IsolationForest(contamination='auto', random_state=42)
iso.fit(X_train_scaled)  # Trained on full train set (supervised data not needed)
```
Changed from `contamination=0.1` (hardcoded, wrong) to `contamination='auto'` (automatically inferred from the data). Note: Isolation Forest does not use SMOTE-balanced data — it is unsupervised and does not use labels.

---

### 3. `src/evaluate_model.py` — Full Rewrite

**The original script** computed accuracy, precision, recall, F1. That was the entirety of the evaluation.

**What was missing:**
- No AUC-ROC score or ROC curve plot
- No False Positive Rate (FPR) — a key requirement from the project plan
- No confusion matrix saved as image
- No `classification_report` (per-class breakdown)
- No success criteria verification (pass/fail against the project thresholds)
- Isolation Forest output is `-1/+1` — this was not converted to `0/1` before evaluation

**What was added:**

#### AUC-ROC + ROC curve plot
```python
y_probs = model.predict_proba(X_test)[:, 1]
auc = roc_auc_score(y_true, y_probs)
fpr_roc, tpr_roc, _ = roc_curve(y_true, y_probs)
plt.savefig(f"../results/roc_{name}.png")
```

#### FPR from confusion matrix
```python
tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
fpr = fp / (fp + tn)
```

#### Isolation Forest output conversion
```python
if name == "Isolation Forest":
    y_pred = np.where(y_pred == -1, 1, 0)
```
Isolation Forest outputs `-1` for anomaly (attack) and `+1` for normal. This line converts that to `1` for attack and `0` for benign, which matches the label encoding used for the other models.

#### Success criteria check — printed after each model
```python
F1 >= 88%  -> PASS / FAIL
Accuracy >= 90% -> PASS / FAIL
FPR < 6%   -> PASS / FAIL
```

#### Final metrics exported to CSV
```python
results_df.to_csv("../results/metrics.csv")
```
A summary table with all metrics for all three models is saved to `results/metrics.csv`.

---

### 4. `src/predict.py` — Updated

Two changes only:

1. **Load the saved scaler** and apply it before prediction:
```python
scaler = joblib.load("../models/scaler.pkl")
X_scaled = scaler.transform(X)
```
Without this, predictions would be made on unscaled data, which would produce completely wrong results since the models were trained on scaled data.

2. **Updated feature list** to match the new 9-feature set + 2 placeholder columns. The old version used a different set of features that no longer matches the trained models.

---

### 5. `src/feature_selection.py` — Updated

Only the feature list was updated to match the new 9-feature schema. The correlation heatmap logic was kept as-is. The output is saved to `results/correlation_heatmap.png`.

---

### 6. `requirements.txt` — 1 Line Added

```diff
+ imbalanced-learn
```

`imbalanced-learn` provides the `SMOTE` class used in `modeltrain.py`. Without installing it, the training script crashes immediately. Install everything with:

```bash
pip install -r requirements.txt
```

---

### 7. `report/` — New Folder (Academic Report)

A full LaTeX report was written documenting this entire pipeline phase. It is split into two files for size reasons:

| File | Content |
|---|---|
| `report/ml_pipeline_report.tex` | Main file — Introduction, Dataset, Features, Preprocessing, Splitting/SMOTE |
| `report/ml_pipeline_report_part2.tex` | Models, K-Fold CV, Evaluation, Results, Isolation Forest analysis, Conclusion |
| `report/figs/` | All 16 figures used in the report (copied from `results/`) |

The report is written in formal academic English and covers:
- Every preprocessing step with the mathematical formula behind it
- Every design decision justified (why median, why capping, why log1p, why fit-on-train-only)
- All results tables including the success criteria verification
- A dedicated section analyzing why Isolation Forest failed on this dataset

To compile: open `report/ml_pipeline_report.tex` in TeXstudio or upload both `.tex` files to Overleaf.

---

## How to Run the Full Pipeline (in order)

```bash
cd src/

# Step 1: Clean and preprocess the data
python data_preprocessing.py
# Output: ../data/preprocessed.csv
#         ../results/class_distribution.png
#         ../results/boxplot_*.png (9 files)

# Step 2: Generate the correlation heatmap
python feature_selection.py
# Output: ../results/correlation_heatmap.png

# Step 3: Train the three models
python modeltrain.py
# Output: ../models/scaler.pkl
#         ../models/random_forest.pkl
#         ../models/xgboost.pkl
#         ../models/isolation_forest.pkl

# Step 4: Evaluate all models
python evaluate_model.py
# Output: ../results/confusion_matrix_*.png (3 files)
#         ../results/roc_random_forest.png
#         ../results/roc_xgboost.png
#         ../results/metrics.csv
```

---

## Results Achieved

| Model | Accuracy | F1-Score | AUC-ROC | FPR | Status |
|---|---|---|---|---|---|
| Random Forest | 99.91% | 99.92% | 0.9997 | 0.11% | ✅ ALL PASS |
| XGBoost | 99.91% | 99.92% | 0.9999 | 0.11% | ✅ ALL PASS |
| Isolation Forest | 18.22% | 7.89% | N/A | 66.94% | ❌ Expected (see below) |

**Why Isolation Forest failed:** It is an unsupervised anomaly detector that expects attacks to be rare (<5%). In this dataset, PortScan is 55% of traffic — it is the majority, not the anomaly. The algorithm is architecturally correct for the project but requires a production environment with genuinely rare, stealthy attacks to perform well. This is documented and explained in the report.
