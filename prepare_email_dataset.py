import os
import pandas as pd


# ==========================================
# CHOOSE YOUR SOURCE DATASET
# ==========================================

# Option 1: Your 10000 CSV dataset
SOURCE_PATH = r"D:\Downloads\email.csv\phishing_legit_dataset_KD_10000.csv"

# Option 2: Your Excel dataset
# SOURCE_PATH = r"D:\Downloads\Email_phishing.csv\phishing_dataset (1).xlsx"

OUTPUT_PATH = "dataset/email_phishing.csv"

os.makedirs("dataset", exist_ok=True)


# ==========================================
# LOAD CSV OR EXCEL
# ==========================================

if SOURCE_PATH.lower().endswith(".csv"):
    df = pd.read_csv(SOURCE_PATH)
elif SOURCE_PATH.lower().endswith(".xlsx"):
    df = pd.read_excel(SOURCE_PATH, engine="openpyxl")
else:
    raise Exception("Unsupported file type. Use CSV or XLSX.")

df.columns = df.columns.str.strip().str.lower()

print("Original Columns:")
print(df.columns.tolist())

print("\nOriginal Rows:", len(df))
print("\nFirst 5 rows:")
print(df.head())


# ==========================================
# DETECT TEXT COLUMN
# ==========================================

possible_text_columns = [
    "email",
    "email_text",
    "text",
    "body",
    "message",
    "content",
    "email body",
    "email_body"
]

text_col = None

for col in possible_text_columns:
    if col in df.columns:
        text_col = col
        break

if text_col is None:
    raise Exception("No email text column found. Need email/email_text/text/body/message/content column.")


# ==========================================
# DETECT LABEL COLUMN
# ==========================================

possible_label_columns = [
    "label",
    "target",
    "class",
    "type",
    "category"
]

label_col = None

for col in possible_label_columns:
    if col in df.columns:
        label_col = col
        break

if label_col is None:
    raise Exception("No label column found. Need label/target/class/type/category column.")


print("\nDetected Text Column:", text_col)
print("Detected Label Column:", label_col)


# ==========================================
# CREATE FINAL DATASET
# ==========================================

df = df[[text_col, label_col]].copy()

df = df.rename(columns={
    text_col: "email",
    label_col: "label"
})

df["email"] = df["email"].astype(str)

df["label"] = df["label"].astype(str).str.lower().str.strip()

df["label"] = df["label"].replace({
    "legitimate": 0,
    "legit": 0,
    "safe": 0,
    "ham": 0,
    "normal": 0,
    "benign": 0,
    "not phishing": 0,
    "non-phishing": 0,

    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "spam": 1,
    "unsafe": 1,
    "fraud": 1
})

df["label"] = pd.to_numeric(df["label"], errors="coerce")

df = df.dropna()
df["label"] = df["label"].astype(int)

df = df[df["label"].isin([0, 1])]
df = df[df["email"].str.strip() != ""]
df = df.drop_duplicates()

df.to_csv(OUTPUT_PATH, index=False)

print("\nDataset Created Successfully")
print("Saved at:", OUTPUT_PATH)

print("\nFinal Columns:")
print(df.columns.tolist())

print("\nFinal Rows:", len(df))

print("\nLabel Count:")
print(df["label"].value_counts())

print("\nSample:")
print(df.head())