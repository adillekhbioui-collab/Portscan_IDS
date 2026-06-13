import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from config import FEATURES

try:
    df = pd.read_csv("../data/preprocessed.csv")
except FileNotFoundError:
    df = pd.read_csv("../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    df.columns = [col.strip() for col in df.columns]

X = df[FEATURES].copy()
X['shadow_node_interaction'] = 0
X['mtd_port_delta'] = 0

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median())

corr = X.corr(numeric_only=True)
print(corr)

plt.figure(figsize=(10, 8))
sns.heatmap(
    corr,
    annot=True,
    cmap="coolwarm",
    fmt=".2f"
)

plt.title("Feature Correlation Heatmap")
plt.tight_layout()
plt.savefig("../results/correlation_heatmap.png", dpi=300, bbox_inches="tight")
plt.close()

print("Heatmap saved to results/correlation_heatmap.png")