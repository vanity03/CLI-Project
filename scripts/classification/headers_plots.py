import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

df = pd.read_csv("scripts\\classification\\datasets\\domain_dataset2.csv", header=0, na_values=["?"])

top_servers_0 = df[df["Class"] == 0]["SSL_Issuer"].value_counts().head(5)
top_servers_1 = df[df["Class"] == 1]["SSL_Issuer"].value_counts().head(5)

all_top_servers = list(set(top_servers_0.index).union(set(top_servers_1.index)))

counts_0 = [df[(df["Class"] == 0) & (df["SSL_Issuer"] == s)].shape[0] for s in all_top_servers]
counts_1 = [df[(df["Class"] == 1) & (df["SSL_Issuer"] == s)].shape[0] for s in all_top_servers]

total_counts = [c0 + c1 for c0, c1 in zip(counts_0, counts_1)]
sorted_data = sorted(zip(all_top_servers, counts_0, counts_1, total_counts), key=lambda x: x[3], reverse=True)

servers_sorted, counts_0_sorted, counts_1_sorted, _ = zip(*sorted_data)

x = np.arange(len(servers_sorted))
width = 0.35

plt.figure(figsize=(12, 6))
plt.bar(x - width/2, counts_0_sorted, width, label='Benígne (Trieda 0)', color='skyblue')
plt.bar(x + width/2, counts_1_sorted, width, label='Škodlivé (Trieda 1)', color='salmon')

plt.xticks(x, servers_sorted, rotation=45)
plt.ylabel("Počet domén")
plt.xlabel("SSL poskytovateľ")
plt.title("Poskytovatelia SSL certifikátov - benígne / škodlivé")
plt.legend()
plt.tight_layout()
plt.savefig("ssl_class_comparison_sorted.png")
plt.show()
