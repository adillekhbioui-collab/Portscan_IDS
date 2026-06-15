# ============================================
# AEGIS — Bridge Module
# Connects: CSV/Nmap input → ML Detection → Dashboard + Deception
# ============================================
# This is the integration middleware that takes feature vectors
# (from CSV, Nmap XML, or live capture), runs them through the
# trained ML model, and dispatches alerts/blocking to the dashboard.
# ============================================

import os
import sys
import json
import threading
import urllib.request
import pandas as pd
import numpy as np
import joblib

# Add project root for config import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

# Import shared preprocessing utilities
detection_src = os.path.join(os.path.dirname(__file__), "..", "detection", "src")
sys.path.insert(0, detection_src)
from preprocessing_utils import load_preprocessing_params, apply_preprocessing


class AegisBridge:
    """Offline bridge: CSV/Nmap → ML prediction → Dashboard dispatch."""

    def __init__(self, model_path=None, scaler_path=None, dashboard_url=None):
        self.model_path = model_path or config.RF_MODEL_PATH
        self.scaler_path = scaler_path or config.SCALER_PATH
        self.dashboard_url = dashboard_url or f"http://localhost:{config.DASHBOARD_PORT}"
        self.features = config.FEATURE_NAMES[:9]  # 9 real features
        self.model = None
        self.scaler = None
        self.preprocessing_params = None

    def load_models(self):
        """Load the trained scaler, classifier, and preprocessing params from disk."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        if not os.path.exists(self.scaler_path):
            raise FileNotFoundError(f"Scaler not found: {self.scaler_path}")

        self.scaler = joblib.load(self.scaler_path)
        self.model = joblib.load(self.model_path)
        print(f"[BRIDGE] Loaded model: {self.model_path}")
        print(f"[BRIDGE] Loaded scaler: {self.scaler_path}")

        preprocessing_params_path = os.path.join(
            os.path.dirname(self.scaler_path), "preprocessing.json"
        )
        if os.path.exists(preprocessing_params_path):
            self.preprocessing_params = load_preprocessing_params(preprocessing_params_path)
            print(f"[BRIDGE] Loaded preprocessing params: {preprocessing_params_path}")
        else:
            print(f"[BRIDGE] Warning: preprocessing params not found at {preprocessing_params_path}")

    def preprocess(self, df):
        """
        Prepare a raw CSV dataframe for prediction:
        1. Strip column names
        2. Extract the 9 real features
        3. Apply saved training preprocessing (median impute, IQR cap, log1p)
        4. Add 2 placeholder columns (shadow_node_interaction, mtd_port_delta)
        5. Scale with the saved StandardScaler
        """
        df.columns = [col.strip() for col in df.columns]

        missing = [f for f in self.features if f not in df.columns]
        if missing:
            raise ValueError(f"Missing features in input: {missing}")

        X = df[self.features].copy()

        # Load scaler/preprocessing if not already loaded
        if self.scaler is None:
            self.load_models()

        # Apply the SAME preprocessing used during training
        if self.preprocessing_params is not None:
            X = apply_preprocessing(X, self.preprocessing_params)
        else:
            # Fallback: basic cleaning only (predictions may be inaccurate)
            X = X.replace([np.inf, -np.inf], np.nan)
            X = X.fillna(X.median())

        # Add placeholders for live integration
        X["shadow_node_interaction"] = 0
        X["mtd_port_delta"] = 0

        # Scale
        X_scaled = self.scaler.transform(X)
        return X_scaled, df

    def predict(self, X_scaled):
        """
        Run prediction and return hard labels + confidence scores.
        Returns: (predictions array, confidence array)
        """
        preds = self.model.predict(X_scaled)

        # Get confidence via predict_proba if available
        try:
            probs = self.model.predict_proba(X_scaled)[:, 1]
        except Exception:
            probs = np.array([1.0 if p == 1 else 0.0 for p in preds])

        return preds, probs

    def _persist_local(self, log_file, entry):
        """Append an entry to a local JSONL log file as fallback."""
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_detection(self, src_ip, dst_port, prediction, confidence, label, action="ALLOW"):
        """
        Persist a detection result to the local JSONL log.
        This is called for EVERY prediction (benign + attack) so the dashboard
        can show live traffic, not only alerts.
        """
        from datetime import datetime
        entry = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": str(src_ip),
            "dst_port": int(dst_port),
            "prediction": int(prediction),
            "confidence": round(float(confidence), 3),
            "label": int(prediction),
            "action": action,
        }
        self._persist_local(config.DETECTION_LOG_FILE, entry)

    def _post_async(self, url, payload, fallback_entry):
        """
        Fire-and-forget POST to the dashboard.
        If the dashboard is reachable the entry is pushed immediately;
        otherwise it will still appear via the local JSONL log (already written).
        """
        def _do_post():
            try:
                req = urllib.request.Request(
                    url,
                    method="POST",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=0.3)
            except Exception as e:
                # Local log is already written; no need to duplicate on timeout.
                pass

        t = threading.Thread(target=_do_post, daemon=True)
        t.start()

    def dispatch_alert(self, src_ip, scan_type, confidence, dst_port=None, honeypot_flag=0):
        """POST an alert to the Flask dashboard asynchronously."""
        from datetime import datetime
        alert = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "scan_type": scan_type,
            "confidence": round(float(confidence), 3),
            "dst_port": dst_port,
            "honeypot_flag": honeypot_flag,
            "prediction": 1,
            "action": "ALERT",
            "label": 1,
        }
        self._post_async(f"{self.dashboard_url}/api/alert", alert, alert)
        return True

    def dispatch_block(self, src_ip, confidence=1.0):
        """POST a block request to the Flask dashboard asynchronously."""
        payload = {"ip": src_ip, "confidence": confidence}
        self._post_async(f"{self.dashboard_url}/api/block", payload, None)
        return True

    def run_csv(self, csv_path, verbose=True, dry_run=False):
        """
        Full pipeline: read CSV → preprocess → predict → dispatch to dashboard.
        Returns a list of result dicts.
        If dry_run is True, predictions are printed but no alerts/blocks are dispatched.
        """
        if self.model is None:
            self.load_models()

        print(f"[BRIDGE] Reading: {csv_path}")
        df = pd.read_csv(csv_path)
        X_scaled, df_raw = self.preprocess(df)

        preds, confs = self.predict(X_scaled)

        results = []
        for i in range(len(preds)):
            pred = int(preds[i])
            conf = float(confs[i])
            src_ip = df_raw.iloc[i].get("Source IP", "192.168.100.10")
            dst_port = int(df_raw.iloc[i].get("Destination Port", 0))

            result = {
                "src_ip": str(src_ip),
                "dst_port": dst_port,
                "prediction": pred,
                "confidence": conf,
                "label": "PortScan" if pred == 1 else "BENIGN",
            }
            results.append(result)

            # Determine action label for the detection log
            if pred == 0:
                action = "ALLOW"
            elif conf >= config.CONFIDENCE_THRESHOLD:
                action = "BLOCK"
            elif conf >= config.ALERT_THRESHOLD:
                action = "ALERT"
            else:
                action = "MONITOR"

            if verbose:
                status = action if pred == 1 else "benign"
                print(f"  [{status}] {src_ip}:{dst_port} -> {result['label']} ({conf:.1%})")

            # Always log the detection result so the dashboard shows live traffic
            if not dry_run:
                self.log_detection(src_ip, dst_port, pred, conf, pred, action=action)

            # Dispatch to dashboard for attack traffic above thresholds
            if not dry_run and pred == 1 and conf >= config.ALERT_THRESHOLD:
                self.dispatch_alert(
                    src_ip=src_ip,
                    scan_type="SYN Scan",
                    confidence=conf,
                    dst_port=dst_port,
                )

                # Auto-block if confidence exceeds threshold
                if conf >= config.CONFIDENCE_THRESHOLD:
                    self.dispatch_block(src_ip, confidence=conf)

        return results


# ============================================
# CLI Entry Point
# ============================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AEGIS Bridge — CSV to ML to Dashboard")
    parser.add_argument("--input", required=True, help="Path to input CSV file")
    parser.add_argument("--model", default=None, help="Path to model .pkl (default: random_forest.pkl)")
    parser.add_argument("--scaler", default=None, help="Path to scaler .pkl")
    parser.add_argument("--dashboard", default=None, help="Dashboard URL (default: http://localhost:5000)")
    parser.add_argument("--dry-run", action="store_true", help="Predict only, don't dispatch to dashboard")
    args = parser.parse_args()

    bridge = AegisBridge(
        model_path=args.model,
        scaler_path=args.scaler,
        dashboard_url=args.dashboard,
    )

    results = bridge.run_csv(args.input, dry_run=args.dry_run)

    # Summary
    alerts = [r for r in results if r["prediction"] == 1]
    benign = [r for r in results if r["prediction"] == 0]
    mode_str = " (DRY RUN — no dispatch)" if args.dry_run else ""
    print(f"\n[BRIDGE] Done{mode_str}. {len(alerts)} alerts, {len(benign)} benign out of {len(results)} flows.")
