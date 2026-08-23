import pandas as pd
import numpy as np
import os
import joblib
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from feature_extraction import extract_features


# ==========================
# USE ONLY DATASETS WITH REAL URL / DOMAIN TEXT
# ==========================

files = [
    r"D:\Downloads\url.csv\dataset3.csv",
    r"D:\Downloads\url.csv\dataset4.csv",
    r"D:\Downloads\url.csv\dataset5.csv"
]


FEATURE_NAMES = [
    "having_ip",
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "dots",
    "subdomains",
    "hyphen",
    "https",
    "shortening",
    "suspicious_tld",
    "at_symbol",
    "slash",
    "question",
    "equal",
    "percent",
    "underscore",
    "dash",
    "amp",
    "digits",
    "special",
    "double_slash",
    "keyword_count",
    "entropy_score",
    "ratio_digits",
    "ratio_special"
]


def convert_label(value):
    value = str(value).strip().lower()

    safe_labels = [
        "0",
        "0.0",
        "-1",
        "-1.0",
        "safe",
        "legitimate",
        "benign",
        "good",
        "normal",
        "clean"
    ]

    phishing_labels = [
        "1",
        "1.0",
        "phishing",
        "malicious",
        "bad",
        "unsafe",
        "spam",
        "attack",
        "defacement",
        "malware"
    ]

    if value in safe_labels:
        return 0

    if value in phishing_labels:
        return 1

    return np.nan


def normalize_url(value):
    try:
        value = str(value).strip()

        if value == "" or value.lower() == "nan":
            return np.nan

        value = value.replace(" ", "")

        if "[" in value or "]" in value:
            return np.nan

        if not value.startswith(("http://", "https://")):
            value = "https://" + value

        parsed = urlparse(value)

        if not parsed.netloc:
            return np.nan

        return value

    except Exception:
        return np.nan


# ==========================
# LOAD DATASETS
# ==========================

frames = []

for file in files:
    try:
        try:
            df = pd.read_csv(file, on_bad_lines="skip")
        except Exception:
            df = pd.read_csv(
                file,
                encoding="latin1",
                engine="python",
                on_bad_lines="skip"
            )

        df.columns = df.columns.str.strip()

        print("\nLoaded:", file)
        print("Rows:", len(df))
        print("Columns:", df.columns.tolist())

        temp = pd.DataFrame()

        # Dataset 3
        if "url" in df.columns and "status" in df.columns:
            temp["url"] = df["url"]
            temp["label"] = df["status"]

        # Dataset 4
        elif "URL" in df.columns and "label" in df.columns:
            temp["url"] = df["URL"]
            temp["label"] = df["label"]

        # Dataset 5
        elif "domain" in df.columns and "label" in df.columns:
            temp["url"] = df["domain"]
            temp["label"] = df["label"]

        else:
            print("Skipped because real URL/domain and label columns not found.")
            continue

        frames.append(temp)

    except Exception as e:
        print("\nSkipped:", file)
        print(e)


if not frames:
    raise Exception("No valid datasets loaded.")


data = pd.concat(frames, ignore_index=True)

print("\nTotal Rows Before Cleaning:", len(data))


# ==========================
# CLEAN DATA
# ==========================

data["url"] = data["url"].apply(normalize_url)
data["target"] = data["label"].apply(convert_label)

data = data.dropna(subset=["url", "target"])
data["target"] = data["target"].astype(int)

data = data.drop_duplicates(subset=["url"])

print("\nFinal Label Distribution:")
print(data["target"].value_counts())

if len(data) == 0:
    raise Exception("No valid rows after cleaning.")

if data["target"].nunique() < 2:
    raise Exception("Dataset must contain both legitimate and phishing samples.")


# ==========================
# EXTRACT FEATURES
# ==========================

print("\nExtracting 26 URL features...")

features = []

for url in data["url"]:
    try:
        features.append(extract_features(url))
    except Exception:
        features.append([0] * len(FEATURE_NAMES))


X = pd.DataFrame(features, columns=FEATURE_NAMES)
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

y = data["target"]

print("\nFeatures:", X.shape[1])
print("Rows:", len(X))

print("\nClass Distribution:")
print(y.value_counts(normalize=True))


# ==========================
# SPLIT
# ==========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================
# MODEL
# ==========================

model = RandomForestClassifier(
    n_estimators=400,
    max_depth=30,
    min_samples_split=8,
    min_samples_leaf=3,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


print("\nTraining...")

model.fit(X_train, y_train)


# ==========================
# EVALUATION
# ==========================

pred = model.predict(X_test)

acc = accuracy_score(y_test, pred)

print("\nAccuracy:", round(acc * 100, 2), "%")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, pred))

print("\nClassification Report:")
print(classification_report(y_test, pred))


# ==========================
# SAVE MODEL
# ==========================

os.makedirs("model", exist_ok=True)

joblib.dump(
    {
        "model": model,
        "features": FEATURE_NAMES
    },
    "model/phishing_model.pkl"
)

print("\nURL Model Saved Successfully")

loaded = joblib.load("model/phishing_model.pkl")

print("Expected Features:", len(loaded["features"]))
print("Feature Names:", loaded["features"])

print("\nTraining Complete")