import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from config import FEATURES

print("==========================")
print("Loading Dataset")
print("==========================")

df = pd.read_csv("../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

# Clean column names (strip leading/trailing spaces)
df.columns = [col.strip() for col in df.columns]

print("Dimensions :", df.shape)
print("\nInfo Dataset :")
print(df[FEATURES].info())
print("\nDescription :")
print(df[FEATURES].describe())

# Replace infinites with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
print("\nMissing values before filling :")
print(df[FEATURES].isnull().sum())

# Fill missing values with median for numeric columns
df[FEATURES] = df[FEATURES].fillna(df[FEATURES].median())

print("\nClasses :")
print(df["Label"].value_counts())

os.makedirs("../results", exist_ok=True)

# 1. Class Distribution Plot
plt.figure(figsize=(8,5))
df["Label"].value_counts().plot(kind="bar", color=['#1f77b4', '#ff7f0e'])
plt.title("Class Distribution")
plt.xlabel("Class")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("../results/class_distribution.png", dpi=300)
plt.close()
print("class_distribution.png generated successfully.")

# 2. Outlier Detection (Boxplots & IQR)
print("\n==========================")
print("Outlier Detection (IQR)")
print("==========================")

for feature in FEATURES:
    # Save boxplot
    plt.figure(figsize=(6,4))
    sns.boxplot(x=df[feature])
    plt.title(f'Boxplot of {feature}')
    plt.tight_layout()
    plt.savefig(f"../results/boxplot_{feature.replace(' ', '_').replace('/', '_')}.png")
    plt.close()
    
    # Calculate IQR
    Q1 = df[feature].quantile(0.25)
    Q3 = df[feature].quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    
    outliers_count = ((df[feature] < lower_bound) | (df[feature] > upper_bound)).sum()
    print(f"{feature}: {outliers_count} outliers detected.")
    
    # Cap outliers instead of removing rows to preserve data
    df[feature] = np.where(df[feature] < lower_bound, lower_bound, df[feature])
    df[feature] = np.where(df[feature] > upper_bound, upper_bound, df[feature])

# 3. Skewness and Log Transform
print("\n==========================")
print("Skewness & Log Transform")
print("==========================")

for feature in FEATURES:
    skewness = df[feature].skew()
    print(f"Skewness of {feature}: {skewness:.2f}")
    if abs(skewness) > 1.0:
        print(f"  -> Applying log transform to {feature}")
        # Use np.log1p (log(1+x)) to handle zeros. Ensure no negative values first.
        min_val = df[feature].min()
        if min_val < 0:
            df[feature] = df[feature] - min_val
        df[feature] = np.log1p(df[feature])

# Save preprocessed data
df.to_csv("../data/preprocessed.csv", index=False)
print("\nPreprocessed dataset saved to ../data/preprocessed.csv")

