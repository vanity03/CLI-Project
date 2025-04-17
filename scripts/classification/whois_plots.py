import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("scripts\\classification\\datasets\\domain_dataset2.csv", header=0, na_values=["?"])

# occurence for different registrars conencted to class 0 and 1
registrar_counts_class_0 = df[df["Class"] == 0]["Registrar"].value_counts().head(5)
registrar_counts_class_1 = df[df["Class"] == 1]["Registrar"].value_counts().head(5)

# Plot for class 0
plt.figure(figsize=(10, 6))
plt.bar(registrar_counts_class_0.index, registrar_counts_class_0.values, color="skyblue")
plt.title("Top 5 registrátorov benígnych domén")
plt.ylabel("Počet")
plt.xlabel("Registrátor")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("registrar_class_0.png") 
plt.show()

# Plot for class 1
plt.figure(figsize=(10, 6))
plt.bar(registrar_counts_class_1.index, registrar_counts_class_1.values, color="salmon")
plt.title("Top 5 registrátorov škodlivých domén")
plt.ylabel("Počet")
plt.xlabel("Registrátor")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("registrar_class_1.png") 
plt.show()