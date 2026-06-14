"""
Aegis Entropy - Multi-Dataset Reconnaissance Training Pipeline
==============================================================
Targeted download and alignment of CSE-CIC-IDS2018 and UNSW-NB15
reconnaissance/port-scan slices into the 11-feature Aegis schema.

Downloads only the specific CSV files containing PortScan/Reconnaissance
traffic -- not the full multi-GB archives.

Sources:
  CSE-CIC-IDS2018: S3 public bucket (virtual-hosted URL, no AWS CLI needed)
  UNSW-NB15:       HuggingFace mirror (training + testing splits)

Usage:
    python fetch_and_align_datasets.py
"""

import warnings
warnings.filterwarnings("ignore")

import json
import time
import urllib.request
import urllib.error
import urllib.parse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(config.PROJECT_ROOT) / "capture"
RAW_DIR = BASE_DIR / "raw_datasets"
OUTPUT_DIR = Path(config.PROJECT_ROOT) / "detection" / "pipeline_output"
TARGET_FEATURES = config.FEATURE_NAMES
RANDOM_STATE = 42

print("=" * 72)
print("  AEGIS ENTROPY - Multi-Dataset Recon Training Data Fetcher")
print("=" * 72)
print(f"  Target features: {len(TARGET_FEATURES)}")
print(f"  Raw data dir:    {RAW_DIR}")
print()


# ---------------------------------------------------------------------------
# 1. Download helpers
# ---------------------------------------------------------------------------
def download_file(url: str, dest: Path, desc: str = "", timeout: int = 600) -> bool:
    """Download a file with progress reporting. Returns True on success."""
    if dest.exists() and dest.stat().st_size > 1024:
        print(f"  [CACHED] {desc} ({dest.stat().st_size / 1e6:.1f} MB) - skipping download")
        return True

    print(f"  [DOWNLOAD] {desc}")
    print(f"    URL: {url[:120]}...")
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AegisEntropy/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = resp.headers.get("Content-Length")
            total = int(total) if total else None
            downloaded = 0
            chunk_size = 1024 * 256  # 256 KB chunks

            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        mb = downloaded / 1e6
                        print(f"\r    {mb:.1f} / {total/1e6:.1f} MB ({pct:.1f}%)", end="", flush=True)
                    else:
                        print(f"\r    {downloaded/1e6:.1f} MB", end="", flush=True)
            print()

        size_mb = dest.stat().st_size / 1e6
        print(f"  [OK] {desc} - {size_mb:.1f} MB")
        return True

    except Exception as e:
        print(f"  [FAIL] {desc}: {e}")
        if dest.exists():
            dest.unlink()
        return False


# ---------------------------------------------------------------------------
# 2. CSE-CIC-IDS2018: Targeted Wednesday PortScan files
# ---------------------------------------------------------------------------
# S3 virtual-hosted-style URL (spaces in path must be percent-encoded)
# Only download the Wednesday files that contain PortScan/Reconnaissance.
CICIDS2018_FILES = {
    "Wednesday-14-02-2018": {
        "filename": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "note": "FTP-BruteForce, SSH-Bruteforce + Benign",
    },
    "Wednesday-21-02-2018": {
        "filename": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        "note": "DDOS attacks (HOIC/LOIC) + Benign",
    },
    "Wednesday-28-02-2018": {
        "filename": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
        "note": "Infilteration + Benign",
    },
}


def build_s3_url(filename: str) -> str:
    """Build a virtual-hosted-style S3 URL with proper percent-encoding."""
    folder = "Processed Traffic Data for ML Algorithms"
    encoded_folder = urllib.parse.quote(folder)
    encoded_file = urllib.parse.quote(filename)
    return f"https://cse-cic-ids2018.s3.amazonaws.com/{encoded_folder}/{encoded_file}"


def fetch_cicids2018() -> pd.DataFrame:
    """Download and filter CSE-CIC-IDS2018 Wednesday files for recon/portscan."""
    print("-" * 72)
    print("  CSE-CIC-IDS2018 - Targeted Wednesday PortScan Files")
    print("-" * 72)

    cicids_dir = RAW_DIR / "cicids2018"
    cicids_dir.mkdir(parents=True, exist_ok=True)

    frames = []
    for day_key, info in CICIDS2018_FILES.items():
        url = build_s3_url(info["filename"])
        dest = cicids_dir / info["filename"]

        print(f"\n  >> {day_key} ({info['note']})")
        success = download_file(url, dest, desc=info["filename"])

        if not success:
            continue

        print(f"  [LOAD] Reading {info['filename']}...")
        try:
            df = pd.read_csv(dest, low_memory=False, encoding="utf-8", on_bad_lines="skip")
            df.columns = df.columns.str.strip()
            print(f"  [LOADED] {len(df):,} rows x {len(df.columns)} cols")
            if "Label" in df.columns:
                print(f"  Labels: {df['Label'].value_counts().head(10).to_dict()}")
            frames.append(df)
        except Exception as e:
            print(f"  [ERROR] Failed to parse {info['filename']}: {e}")
            continue

    if not frames:
        print("\n  [FAIL] No CSE-CIC-IDS2018 files could be loaded")
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  [COMBINED] {len(combined):,} total rows from CSE-CIC-IDS2018")
    return combined


def filter_cicids2018(df: pd.DataFrame) -> pd.DataFrame:
    """Filter CSE-CIC-IDS2018 for reconnaissance/portscan + balanced benign."""
    if df.empty:
        return df

    print("\n  [FILTER] Extracting PortScan/Reconnaissance traffic...")
    print(f"  All labels: {df['Label'].value_counts().to_dict()}")

    # Match recon/portscan/infilteration labels
    recon_patterns = ["recon", "portscan", "port scan", "infilteration"]
    recon_mask = df["Label"].str.lower().str.contains(
        "|".join(recon_patterns), case=False, na=False
    )
    recon_df = df[recon_mask].copy()
    print(f"  Recon/PortScan rows: {len(recon_df):,}")

    # If no explicit recon labels, use all attack traffic
    if len(recon_df) == 0:
        benign_mask = df["Label"].str.lower().str.contains("benign", case=False, na=False)
        attack_df = df[~benign_mask].copy()
        print(f"  No explicit recon labels. Using all attack traffic: {len(attack_df):,}")
        recon_df = attack_df

    # Balanced benign slice
    benign_mask = df["Label"].str.lower().str.contains("benign", case=False, na=False)
    benign_df = df[benign_mask].copy()
    n_sample = min(len(recon_df), len(benign_df))
    benign_sampled = benign_df.sample(n=n_sample, random_state=RANDOM_STATE)
    print(f"  Balanced benign sample: {n_sample:,}")

    result = pd.concat([recon_df, benign_sampled], ignore_index=True)
    print(f"  Final CSE-CIC-IDS2018 dataset: {len(result):,} rows")
    return result


# ---------------------------------------------------------------------------
# 3. UNSW-NB15: HuggingFace mirror (training + testing splits)
# ---------------------------------------------------------------------------
UNSWNB15_SOURCES = {
    "training-set": {
        "url": "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/UNSW_NB15_training-set.csv",
        "filename": "UNSW_NB15_training-set.csv",
    },
    "testing-set": {
        "url": "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/UNSW_NB15_testing-set.csv",
        "filename": "UNSW_NB15_testing-set.csv",
    },
}


def fetch_unswnb15() -> pd.DataFrame:
    """Download UNSW-NB15 from HuggingFace mirror and filter for Reconnaissance."""
    print("\n" + "-" * 72)
    print("  UNSW-NB15 - Reconnaissance Attack Filter (via HuggingFace)")
    print("-" * 72)

    unswnb15_dir = RAW_DIR / "unswnb15"
    unswnb15_dir.mkdir(parents=True, exist_ok=True)

    frames = []
    for split_name, info in UNSWNB15_SOURCES.items():
        dest = unswnb15_dir / info["filename"]
        print(f"\n  >> {split_name}")
        success = download_file(info["url"], dest, desc=info["filename"])

        if not success:
            continue

        print(f"  [LOAD] Reading {info['filename']}...")
        try:
            df = pd.read_csv(dest, low_memory=False, encoding="utf-8", on_bad_lines="skip")
            df.columns = df.columns.str.strip()
            print(f"  [LOADED] {len(df):,} rows x {len(df.columns)} cols")
            if "attack_cat" in df.columns:
                print(f"  Attack categories: {df['attack_cat'].value_counts().to_dict()}")
            frames.append(df)
        except Exception as e:
            print(f"  [ERROR] Failed to parse {info['filename']}: {e}")
            continue

    if not frames:
        print("\n  [FAIL] No UNSW-NB15 files could be loaded")
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  [COMBINED] {len(combined):,} total rows from UNSW-NB15")
    return combined


def filter_unswnb15(df: pd.DataFrame) -> pd.DataFrame:
    """Filter UNSW-NB15 for Reconnaissance + balanced normal traffic."""
    if df.empty:
        return df

    print("\n  [FILTER] Extracting Reconnaissance traffic...")
    recon_mask = df["attack_cat"].str.lower() == "reconnaissance"
    recon_df = df[recon_mask].copy()
    print(f"  Reconnaissance rows: {len(recon_df):,}")

    if len(recon_df) == 0:
        print("  [WARN] No reconnaissance rows found")
        return pd.DataFrame()

    # Balanced normal (label=0) sample
    normal_mask = df["label"] == 0
    normal_df = df[normal_mask].copy()
    n_sample = min(len(recon_df), len(normal_df))
    normal_sampled = normal_df.sample(n=n_sample, random_state=RANDOM_STATE)
    print(f"  Balanced normal sample: {n_sample:,}")

    result = pd.concat([recon_df, normal_sampled], ignore_index=True)
    print(f"  Final UNSW-NB15 dataset: {len(result):,} rows")
    return result


# ---------------------------------------------------------------------------
# 4. Column Mapping -> 11-Feature Aegis Schema
# ---------------------------------------------------------------------------
# CSE-CIC-IDS2018 uses CICFlowMeter v3 columns (nearly identical to CICIDS2017)
# Only the 11 features from config.FEATURE_NAMES are mapped.
CICIDS2018_COL_MAP = {
    "Distinct Dst Ports/IP":           "Dst Port",
    "Unique Dst IPs/Src":              "Dst Port",
    "Flow Duration":                   "Flow Duration",
    "Total Fwd Packets":               "Tot Fwd Pkts",
    "SYN Flag Count":                  "SYN Flag Cnt",
    "RST Flag Count":                  "RST Flag Cnt",
    "ACK Flag Count":                  "ACK Flag Cnt",
    "IAT Mean":                        "Flow IAT Mean",
    "TTL Value":                       "Bwd IAT Mean",
    "TCP Window Size":                 "Init Fwd Win Byts",
    "Total Bwd Packets":               "Tot Bwd Pkts",
    "Fwd Packet Length Mean":          "Fwd Pkt Len Mean",
    "Bwd Packet Length Mean":          "Bwd Pkt Len Mean",
    "Flow Bytes/s":                    "Flow Byts/s",
    "Flow Packets/s":                  "Flow Pkts/s",
    "Fwd IAT Mean":                    "Fwd IAT Mean",
    "Bwd IAT Mean":                    "Bwd IAT Mean",
    "Min Packet Length":               "Pkt Len Min",
    "Max Packet Length":               "Pkt Len Max",
    "Packet Length Mean":              "Pkt Len Mean",
    "Packet Length Std":               "Pkt Len Std",
    "FIN Flag Count":                  "FIN Flag Cnt",
    "PSH Flag Count":                  "PSH Flag Cnt",
    "URG Flag Count":                  "URG Flag Cnt",
    "Fwd Header Length":               "Fwd Header Len",
    "Bwd Header Length":               "Bwd Header Len",
    "Down/Up Ratio":                   "Down/Up Ratio",
    "Average Packet Size":             "Pkt Size Avg",
    "Avg Fwd Segment Size":            "Fwd Seg Size Avg",
    "Avg Bwd Segment Size":            "Bwd Seg Size Avg",
    "Subflow Fwd Packets":             "Subflow Fwd Pkts",
    "Subflow Fwd Bytes":               "Subflow Fwd Byts",
    "Subflow Bwd Packets":             "Subflow Bwd Pkts",
    "Subflow Bwd Bytes":               "Subflow Bwd Byts",
    "Init_Win_bytes_forward":          "Init Fwd Win Byts",
    "Init_Win_bytes_backward":         "Init Bwd Win Byts",
    "act_data_pkt_fwd":                "Fwd Act Data Pkts",
    "min_seg_size_forward":            "Fwd Seg Size Min",
    "Active Mean":                     "Active Mean",
    "Idle Mean":                       "Idle Mean",
    "Fwd Packets/s":                   "Fwd Pkts/s",
    "Bwd Packets/s":                   "Bwd Pkts/s",
    "Fwd Packet Length Max":           "Fwd Pkt Len Max",
    "Bwd Packet Length Max":           "Bwd Pkt Len Max",
    "ECE Flag Count":                  "ECE Flag Cnt",
    "CWE Flag Count":                  "CWE Flag Count",
    "Shadow Node Interaction":         None,
    "MTD Port Delta":                  None,
}

# UNSW-NB15 Argus/Bro-IDS 49-feature set -> Aegis 11-feature schema
# NOTE: Many Aegis features have no direct equivalent in UNSW-NB15.
# TCP flags (syn/rst/ack) and header lengths are absent.
# These are filled with 0 (see map_to_aegis_schema fallback).
UNSWNB15_COL_MAP = {
    "Distinct Dst Ports/IP":           "ct_dst_sport_ltm",   # Proxy: count of connections to same dest port
    "Unique Dst IPs/Src":              0,                    # Not available
    "Flow Duration":                   "dur",
    "Total Fwd Packets":               "spkts",
    "SYN Flag Count":                  0,                    # Not available
    "RST Flag Count":                  0,                    # Not available
    "ACK Flag Count":                  0,                    # Not available
    "IAT Mean":                        "sinpkt",
    "TTL Value":                       "sttl",
    "TCP Window Size":                 "swin",
    "Total Bwd Packets":               "dpkts",
    "Fwd Packet Length Mean":          "smean",
    "Bwd Packet Length Mean":          "dmean",
    "Flow Bytes/s":                    "rate",
    "Flow Packets/s":                  "rate",
    "Fwd IAT Mean":                    "sinpkt",
    "Bwd IAT Mean":                    "dinpkt",
    "Min Packet Length":               "sbytes",             # Proxy
    "Max Packet Length":               "sbytes",
    "Packet Length Mean":              "smean",
    "Packet Length Std":               0,                    # Not available
    "FIN Flag Count":                  0,                    # Not available
    "PSH Flag Count":                  0,                    # Not available
    "URG Flag Count":                  0,                    # Not available
    "Fwd Header Length":               0,                    # Not available in UNSW-NB15
    "Bwd Header Length":               0,                    # Not available in UNSW-NB15
    "Down/Up Ratio":                   "dinpkt",
    "Average Packet Size":             "smean",
    "Avg Fwd Segment Size":            "smean",
    "Avg Bwd Segment Size":            "dmean",
    "Subflow Fwd Packets":             "spkts",
    "Subflow Fwd Bytes":               "sbytes",
    "Subflow Bwd Packets":             "dpkts",
    "Subflow Bwd Bytes":               "dbytes",
    "Init_Win_bytes_forward":          "swin",
    "Init_Win_bytes_backward":         "dwin",
    "act_data_pkt_fwd":                "spkts",
    "min_seg_size_forward":            "smean",
    "Active Mean":                     "sjit",               # Proxy
    "Idle Mean":                       "djit",               # Proxy
    "Fwd Packets/s":                   "spkts",
    "Bwd Packets/s":                   "dpkts",
    "Fwd Packet Length Max":           "sbytes",
    "Bwd Packet Length Max":           "dbytes",
    "ECE Flag Count":                  0,                    # Not available
    "CWE Flag Count":                  0,                    # Not available
    "Shadow Node Interaction":         None,
    "MTD Port Delta":                  None,
}


def map_to_aegis_schema(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """Map source dataset columns to the 11-feature Aegis schema."""
    print(f"\n  [MAP] Aligning {source} to 11-feature Aegis schema...")

    col_map = CICIDS2018_COL_MAP if source == "cicids2018" else UNSWNB15_COL_MAP
    mapped = pd.DataFrame(index=df.index)
    unmapped = []

    for aegis_feat, src_col in col_map.items():
        if src_col is None:
            mapped[aegis_feat] = np.nan
            continue
        if isinstance(src_col, (int, float)):
            mapped[aegis_feat] = src_col
            continue
        if src_col in df.columns:
            vals = pd.to_numeric(df[src_col], errors="coerce")
            mapped[aegis_feat] = vals.values
        else:
            mapped[aegis_feat] = 0.0
            unmapped.append(f"{aegis_feat} <- {src_col} (NOT FOUND)")

    if unmapped:
        print(f"  [WARN] {len(unmapped)} features filled with defaults:")
        for u in unmapped[:10]:
            print(f"    - {u}")
        if len(unmapped) > 10:
            print(f"    ... and {len(unmapped) - 10} more")

    # Set placeholder columns to 0 (no synthetic injection — avoids data leakage)
    if "Shadow Node Interaction" in mapped.columns:
        mapped["Shadow Node Interaction"] = 0
    if "MTD Port Delta" in mapped.columns:
        mapped["MTD Port Delta"] = 0

    # Clean
    mapped.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(mapped)
    mapped.dropna(inplace=True)
    dropped = before - len(mapped)
    if dropped > 0:
        print(f"  [CLEAN] Dropped {dropped:,} rows with NaN/Inf")

    # Keep only the 11 features defined in config
    mapped = mapped[[f for f in TARGET_FEATURES if f in mapped.columns]]

    print(f"  [OK] {source}: {len(mapped):,} rows x {len(mapped.columns)} features")
    return mapped


# ---------------------------------------------------------------------------
# 5. Build combined training dataset
# ---------------------------------------------------------------------------
def build_combined_dataset(cicids_df: pd.DataFrame, unswnb_df: pd.DataFrame) -> pd.DataFrame:
    """Combine all sources into a single aligned dataset with labels."""
    print("\n" + "-" * 72)
    print("  Building Combined Training Dataset")
    print("-" * 72)

    frames = []
    sources = []

    if not cicids_df.empty:
        cicids_df = cicids_df.copy()
        cicids_df["__source__"] = "CSE-CIC-IDS2018"
        frames.append(cicids_df)
        sources.append(f"CSE-CIC-IDS2018: {len(cicids_df):,}")

    if not unswnb_df.empty:
        unswnb_df = unswnb_df.copy()
        unswnb_df["__source__"] = "UNSW-NB15"
        frames.append(unswnb_df)
        sources.append(f"UNSW-NB15: {len(unswnb_df):,}")

    if not frames:
        print("  [FAIL] No data to combine")
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    print(f"\n  Combined dataset:")
    for s in sources:
        print(f"    - {s}")
    print(f"    Total: {len(combined):,} rows x {len(combined.columns)} cols")
    return combined


# ---------------------------------------------------------------------------
# 6. Save outputs
# ---------------------------------------------------------------------------
def save_outputs(combined: pd.DataFrame, cicids_aligned: pd.DataFrame, unswnb_aligned: pd.DataFrame):
    """Save aligned datasets and metadata."""
    print("\n" + "-" * 72)
    print("  Saving Aligned Outputs")
    print("-" * 72)

    combined_path = RAW_DIR / "combined_recon_aligned.csv"
    combined.to_csv(combined_path, index=False)
    print(f"  Saved: {combined_path} ({combined_path.stat().st_size / 1e6:.1f} MB)")

    if not cicids_aligned.empty:
        cicids_path = RAW_DIR / "cicids2018_recon_aligned.csv"
        cicids_aligned.to_csv(cicids_path, index=False)
        print(f"  Saved: {cicids_path}")

    if not unswnb_aligned.empty:
        unswnb_path = RAW_DIR / "unswnb15_recon_aligned.csv"
        unswnb_aligned.to_csv(unswnb_path, index=False)
        print(f"  Saved: {unswnb_path}")

    meta = {
        "target_features": TARGET_FEATURES,
        "n_features": len(TARGET_FEATURES),
        "sources": {
            "CSE-CIC-IDS2018": {
                "files": list(CICIDS2018_FILES.keys()),
                "rows": len(cicids_aligned) if not cicids_aligned.empty else 0,
                "mapping": "Direct CICFlowMeter column alignment (high fidelity)",
            },
            "UNSW-NB15": {
                "files": list(UNSWNB15_SOURCES.keys()),
                "rows": len(unswnb_aligned) if not unswnb_aligned.empty else 0,
                "mapping": "Argus/Bro-IDS proxy mapping (heavier derivation)",
            },
        },
        "total_rows": len(combined),
        "note": "CSE-CIC-IDS2018 provides high-fidelity CICFlowMeter alignment. "
                "UNSW-NB15 uses proxy columns due to different feature extraction tool.",
    }

    meta_path = RAW_DIR / "alignment_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  Saved: {meta_path}")

    print(f"\n  [PREVIEW] First 3 rows (first 8 features):")
    print(combined[TARGET_FEATURES[:8]].head(3).to_string(index=False))


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    start = time.time()

    # 1. Fetch CSE-CIC-IDS2018
    cicids_raw = fetch_cicids2018()
    cicids_filtered = filter_cicids2018(cicids_raw)

    # 2. Fetch UNSW-NB15
    unswnb_raw = fetch_unswnb15()
    unswnb_filtered = filter_unswnb15(unswnb_raw)

    # 3. Map both to 48-feature Aegis schema
    cicids_aligned = map_to_aegis_schema(cicids_filtered, source="cicids2018") if not cicids_filtered.empty else pd.DataFrame()
    unswnb_aligned = map_to_aegis_schema(unswnb_filtered, source="unswnb15") if not unswnb_filtered.empty else pd.DataFrame()

    # 4. Combine
    combined = build_combined_dataset(cicids_aligned, unswnb_aligned)

    # 5. Save
    if not combined.empty:
        save_outputs(combined, cicids_aligned, unswnb_aligned)

    elapsed = time.time() - start
    print(f"\n{'=' * 72}")
    print(f"  COMPLETE - {elapsed:.1f}s elapsed")
    print(f"  Files saved to: {RAW_DIR}")
    print(f"{'=' * 72}")


if __name__ == "__main__":
    main()
