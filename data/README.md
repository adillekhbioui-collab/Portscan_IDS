# Dataset Directory

**Do NOT push datasets to GitHub** — they are too large.

Each team member must download locally:

## CICIDS2017 — PortScan Subset
- **Source:** https://www.unb.ca/cic/datasets/ids-2017.html
- **File:** `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- **Size:** ~158,000 flows
- **Place in:** `data/cicids2017_portscan.csv`

## UNSW-NB15 — Reconnaissance Category
- **Source:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Files:** Filter for `attack_cat == 'Reconnaissance'`
- **Size:** ~13,000 records
- **Place in:** `data/unsw_nb15_recon.csv`

## After Download

Your `data/` folder should look like:
```
data/
├── README.md              ← this file
├── cicids2017_portscan.csv
└── unsw_nb15_recon.csv
```

The `.gitignore` ensures CSV files are never pushed.
