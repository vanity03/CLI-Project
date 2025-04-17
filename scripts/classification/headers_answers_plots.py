import pandas as pd
import matplotlib.pyplot as plt

# Load data
df = pd.read_csv("scripts\\classification\\datasets\\domain_dataset2.csv", header=0, na_values=["?"])
df.dropna(inplace=True)

# Count HTTP Status codes for class 0 (benign) and class 1 (malicious)
http_status_class_0 = df[df["Class"] == 0]["HTTP_Status"].astype(str).str[:1].value_counts().sort_index()
http_status_class_1 = df[df["Class"] == 1]["HTTP_Status"].astype(str).str[:1].value_counts().sort_index()

# Prepare the labels for the status codes (e.g., 2xx, 3xx, 4xx, 5xx)
labels = ['2xx', '3xx', '4xx', '5xx']

# Prepare counts for each range (2xx, 3xx, 4xx, 5xx)
counts_0 = [http_status_class_0.get(str(i), 0) for i in range(2, 6)]  # Counts for class 0
counts_1 = [http_status_class_1.get(str(i), 0) for i in range(2, 6)]  # Counts for class 1

# Plot for class 0 (benign domains)
plt.figure(figsize=(10, 6))
x = range(len(labels))
plt.bar(x, counts_0, width=0.4, color="skyblue", label="Benígne (Trieda 0)", align="center")
plt.bar(x, counts_1, width=0.4, color="salmon", label="Škodlivé (Trieda 1)", align="edge")
plt.xticks(x, labels)
plt.title("HTTP status kódy pre benígne a škodlivé domény")
plt.ylabel("Počet domén")
plt.xlabel("HTTP status kódy")
plt.legend()
plt.tight_layout()
plt.savefig("HTTP_Status_class_comparison.png")
plt.show()
