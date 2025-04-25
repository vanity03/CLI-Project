import pandas as pd

file = "scripts\\classification\\datasets\\dataset2.csv"

df = pd.read_csv(file, header=0, na_values=["?"])
df.dropna(inplace=True)

print(df["Class"].value_counts())
