import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Chargement du dataset
df = pd.read_csv(
    "../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

# Features sélectionnées
features = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' SYN Flag Count',
    ' RST Flag Count',
    ' ACK Flag Count',
    ' Flow IAT Mean',
    ' Bwd Packet Length Mean'
]

X = df[features]

# Nettoyage
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# Matrice de corrélation
corr = X.corr(numeric_only=True)

print(corr)

# Création du graphique
plt.figure(figsize=(10, 8))

sns.heatmap(
    corr,
    annot=True,
    cmap="coolwarm",
    fmt=".2f"
)

plt.title("Feature Correlation Heatmap")

plt.tight_layout()

plt.savefig(
    "../results/correlation_heatmap.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("Heatmap enregistrée dans results/")