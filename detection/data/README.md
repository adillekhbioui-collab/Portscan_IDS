# Data Directory

The AegisEntropy pipeline expects the following file in this directory:

```
data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv   (~73 MB, 286k flows)
```

This is the **PortScan capture (Friday afternoon)** from the **CICIDS2017** dataset by the
Canadian Institute for Cybersecurity (University of New Brunswick).

CSV files in this folder are **gitignored** (`data/*.csv`) because of their size — every
clone must obtain the dataset separately.

## How to get it

- **Official source** (requires filling the request form):
  https://www.unb.ca/cic/datasets/ids-2017.html
- **Hugging Face mirror** (direct download, no form):

  ```
  curl -L -o data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv \
    https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  ```

## Generated files

- `preprocessed.csv` — written by `src/data_preprocessing.py` (run from inside `src/`);
  consumed by `feature_selection.py`, `modeltrain.py`, and `evaluate_model.py`.

## Citation

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New
> Intrusion Detection Dataset and Intrusion Traffic Characterization", 4th International
> Conference on Information Systems Security and Privacy (ICISSP), 2018.
