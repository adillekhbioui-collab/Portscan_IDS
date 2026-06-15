import os
import argparse
import pandas as pd
import numpy as np
import joblib
from config import FEATURES

# Resolve project root so default model/scaler paths point to the shared artifacts
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_model(path):
    return joblib.load(path)


def preprocess(df, scaler):
    # Strip spaces from columns
    df.columns = [col.strip() for col in df.columns]
    
    # Check if we have the needed features, else try to create them (except distinct/ttl)
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"Missing features in input CSV: {missing}")
        
    X = df[FEATURES].copy()
    
    # Add placeholders if they don't exist in live traffic CSV
    if 'shadow_node_interaction' not in X.columns:
        X['shadow_node_interaction'] = 0
    if 'mtd_port_delta' not in X.columns:
        X['mtd_port_delta'] = 0
        
    # Replace inf and fill NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    
    # Scale
    if scaler:
        X_scaled = scaler.transform(X)
        return X_scaled
    return X


def main():
    parser = argparse.ArgumentParser(description="Load a model and run predictions on a CSV input")
    parser.add_argument("--model", default=None, help="Path to model file (joblib)")
    parser.add_argument("--scaler", default=None, help="Path to StandardScaler file")
    parser.add_argument("--input", required=True, help="CSV input file with the required features")
    parser.add_argument("--output", default=None, help="CSV output path (if omitted prints head)" )

    args = parser.parse_args()

    # Default model/scaler paths point to the shared artifacts used by the bridge
    if args.model is None:
        model_path = os.path.join(PROJECT_ROOT, "models", "saved", "rf_model.pkl")
    else:
        model_path = args.model

    if args.scaler is None:
        scaler_path = os.path.join(PROJECT_ROOT, "models", "saved", "scaler.pkl")
    else:
        scaler_path = args.scaler

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler not found: {scaler_path}. The model requires the saved StandardScaler.")

    print(f"Loading scaler from: {scaler_path}")
    scaler = load_model(scaler_path)

    print(f"Loading model from: {model_path}")
    model = load_model(model_path)

    print(f"Reading input CSV: {args.input}")
    df = pd.read_csv(args.input)

    X_scaled = preprocess(df, scaler)

    print("Running prediction...")
    preds = model.predict(X_scaled)

    # Convert IsoForest
    if "isolation_forest" in model_path.lower():
        preds = np.where(preds == -1, 1, 0)

    df_result = df.copy()
    df_result["prediction"] = preds

    if args.output:
        df_result.to_csv(args.output, index=False)
        print(f"Predictions saved to: {args.output}")
    else:
        print("Predictions (1 = PortScan, 0 = BENIGN):")
        print(df_result[["Destination Port", "prediction"]].head())


if __name__ == "__main__":
    main()

