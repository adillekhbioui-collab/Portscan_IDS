"""
Preprocessing utilities shared between training and inference.

The ML models were trained on data that underwent:
  1. Median imputation of NaN/inf values
  2. IQR-based Winsorization (outlier capping)
  3. log1p transform for highly skewed features
  4. StandardScaler fit on the training set

To get correct predictions on new data, the SAME preprocessing steps 1-3
must be applied BEFORE scaling. This module computes, saves, and loads the
parameters needed to repeat that preprocessing exactly.
"""
import os
import json
import numpy as np
import pandas as pd


def compute_preprocessing_params(df, features, output_path=None):
    """
    Compute preprocessing parameters from a training dataframe.

    Parameters
    ----------
    df : pandas.DataFrame
        Training data (raw, before preprocessing).
    features : list
        List of feature column names.
    output_path : str, optional
        If given, save the parameters to this JSON path.

    Returns
    -------
    dict
        Dictionary with keys: medians, bounds, log_transform.
    """
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    # 1. Replace inf -> NaN, compute medians
    df[features] = df[features].replace([np.inf, -np.inf], np.nan)
    medians = df[features].median().to_dict()
    df[features] = df[features].fillna(medians)

    # 2. IQR bounds
    bounds = {}
    for feature in features:
        q1 = df[feature].quantile(0.25)
        q3 = df[feature].quantile(0.75)
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        bounds[feature] = {"lower": float(lower), "upper": float(upper)}

    # 3. Skewness / log transform
    log_transform = {}
    for feature in features:
        skewness = df[feature].skew()
        if abs(skewness) > 1.0:
            min_val = float(df[feature].min())
            shift = -min_val if min_val < 0 else 0.0
            log_transform[feature] = {"shift": shift}

    params = {
        "features": features,
        "medians": medians,
        "bounds": bounds,
        "log_transform": log_transform,
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(params, f, indent=2)

    return params


def load_preprocessing_params(path):
    """Load preprocessing parameters from a JSON file."""
    with open(path, "r") as f:
        return json.load(f)


def apply_preprocessing(df, params):
    """
    Apply saved preprocessing parameters to a new dataframe.

    Returns a new dataframe with the same columns, preprocessed.
    """
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    features = params["features"]

    # 1. Impute with training medians
    df[features] = df[features].replace([np.inf, -np.inf], np.nan)
    for feature in features:
        df[feature] = df[feature].fillna(params["medians"][feature])

    # 2. Winsorize using training bounds
    for feature in features:
        lower = params["bounds"][feature]["lower"]
        upper = params["bounds"][feature]["upper"]
        df[feature] = np.where(df[feature] < lower, lower, df[feature])
        df[feature] = np.where(df[feature] > upper, upper, df[feature])

    # 3. log1p transform for skewed features
    for feature, cfg in params["log_transform"].items():
        if cfg.get("shift", 0.0) > 0:
            df[feature] = df[feature] + cfg["shift"]
        df[feature] = np.log1p(df[feature])

    return df
