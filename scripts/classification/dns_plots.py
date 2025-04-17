import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("scripts\\classification\\datasets\\domain_dataset2.csv", header=0, na_values=["?"])
df.dropna(inplace=True)

# Count SPF usage for class 0 (benign) and class 1 (malicious)
dmarc_counts_class_0 = df[df["Class"] == 0]["DKIM"].value_counts().sort_index()
dmarc_counts_class_1 = df[df["Class"] == 1]["DKIM"].value_counts().sort_index()

# Plot for class 0 (benign domains)
plt.figure(figsize=(10, 6))
plt.bar(["0 - Nepoužili", "1 - Použili"], dmarc_counts_class_0.values, color="skyblue")
plt.title("Využitie DKIM benígnymi doménami")
plt.ylabel("Počet domén")
plt.xlabel("DKIM")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("dkim_class_0.png")
plt.show()

# Plot for class 1 (malicious domains)
plt.figure(figsize=(10, 6))
plt.bar(["0 - Nepoužili", "1 - Použili"], dmarc_counts_class_1.values, color="salmon")
plt.title("Využitie DKIM škodlivými doménami")
plt.ylabel("Počet domén")
plt.xlabel("DKIM")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("dkim_class_1.png")
plt.show()
