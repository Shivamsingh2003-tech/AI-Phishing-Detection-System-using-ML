import pandas as pd

df = pd.read_csv(r"D:\Downloads\url.csv\dataset1.csv")

print("Columns:")
print(df.columns)

print("\nFirst 5 Rows:")
print(df.head())

print("\nUnique values in status:")
print(df['status'].unique())

print("\nValue counts:")
print(df['status'].value_counts())