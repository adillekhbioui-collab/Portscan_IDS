import os
import argparse
import pandas as pd
import numpy as np
import joblib


FEATURES = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' SYN Flag Count',
    ' RST Flag Count',
    ' ACK Flag Count',
    ' Flow IAT Mean',
    ' Bwd Packet Length Mean'
]


def load_model(path):
    return joblib.load(path)


def preprocess(df):
    X = df[FEATURES].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    return X


def main():
    parser = argparse.ArgumentParser(description="Load a model and run predictions on a CSV input")
    parser.add_argument("--model", default=None, help="Path to model file (joblib)")
    parser.add_argument("--input", required=True, help="CSV input file with the required features")
    parser.add_argument("--output", default=None, help="CSV output path (if omitted prints head)" )

    args = parser.parse_args()

    # Default model path (relative to repo root when running from project root)
    if args.model is None:
        default_model = os.path.join(os.path.dirname(__file__), "..", "models", "random_forest.pkl")
        model_path = os.path.normpath(default_model)
    else:
        model_path = args.model

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    print(f"Loading model from: {model_path}")
    model = load_model(model_path)

    print(f"Reading input CSV: {args.input}")
    df = pd.read_csv(args.input)

    X = preprocess(df)

    print("Running prediction...")
    preds = model.predict(X)

    # For anomaly detectors like IsolationForest the output might be -1/1
    # We don't alter the raw predictions here, we just attach them to the frame.
    df_result = df.copy()
    df_result["prediction"] = preds

    if args.output:
        df_result.to_csv(args.output, index=False)
        print(f"Predictions saved to: {args.output}")
    else:
        print(df_result[[*FEATURES, "prediction"]].head())


if __name__ == "__main__":
    main()
