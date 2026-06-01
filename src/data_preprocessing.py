import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ==========================
# Chargement du dataset
# ==========================

df = pd.read_csv(
    "../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)

# ==========================
# Informations générales
# ==========================

print("Dimensions :", df.shape)

print("\nInfo Dataset :")
print(df.info())

print("\nDescription :")
print(df.describe())

print("\nValeurs manquantes :")
print(df.isnull().sum())

# Remplacement des infinis

df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

# ==========================
# Distribution des classes
# ==========================

print("\nClasses :")
print(df[" Label"].value_counts())

# ==========================
# Graphique
# ==========================

plt.figure(figsize=(8,5))

df[" Label"].value_counts().plot(
    kind="bar"
)

plt.title("Class Distribution")
plt.xlabel("Class")
plt.ylabel("Count")

plt.tight_layout()

plt.savefig(
    "../results/class_distribution.png",
    dpi=300
)

plt.close()

print("\nclass_distribution.png généré avec succès.")
