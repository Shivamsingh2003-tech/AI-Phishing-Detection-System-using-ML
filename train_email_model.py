import os
import joblib
import numpy as np
import pandas as pd

from xgboost import XGBClassifier

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

from email_feature_extraction import extract_email_features


DATASET_PATH = "dataset/email_phishing.csv"
MODEL_PATH = "model/email_phishing_model.pkl"

FEATURES = [
    "links",
    "short_links",
    "ip_links",
    "urgent_words",
    "credential_words",
    "sender_score",
    "fake_sender",
    "capital_letters",
    "exclamations",
    "email_length",
    "digits",
    "special_chars",
    "money_score",
    "attachments"
]

TARGET = "label"


# ==========================================
# LOAD DATASET
# ==========================================

df = pd.read_csv(DATASET_PATH)
df.columns = df.columns.str.strip().str.lower()

print("CSV COLUMNS:", df.columns.tolist())

if "email" not in df.columns:
    raise Exception("Dataset must contain 'email' column")

if TARGET not in df.columns:
    raise Exception("Dataset must contain 'label' column")


# ==========================================
# CLEAN DATA
# ==========================================

df = df[["email", TARGET]].copy()

df["email"] = df["email"].astype(str)
df[TARGET] = pd.to_numeric(df[TARGET], errors="coerce")

df = df.dropna()
df[TARGET] = df[TARGET].astype(int)

df = df[df[TARGET].isin([0, 1])]
df = df[df["email"].str.strip() != ""]
df = df.drop_duplicates()

if df[TARGET].nunique() < 2:
    raise Exception("Dataset must contain both classes 0 and 1")


# ==========================================
# EXTRACT MANUAL FEATURES
# ==========================================

manual_features = []

for text in df["email"]:
    features = extract_email_features(text)
    manual_features.append(features)

manual_df = pd.DataFrame(manual_features)
manual_df = manual_df.reindex(columns=FEATURES, fill_value=0)

for col in FEATURES:
    manual_df[col] = pd.to_numeric(manual_df[col], errors="coerce").fillna(0)


# ==========================================
# COMBINE TEXT + MANUAL FEATURES
# ==========================================

X = pd.concat(
    [
        df["email"].reset_index(drop=True).rename("email_text"),
        manual_df.reset_index(drop=True)
    ],
    axis=1
)

y = df[TARGET].reset_index(drop=True)

print("\nRows:", len(X))
print("Model Mode: hybrid_text_numeric")

print("\nClass Distribution:")
print(y.value_counts())


# ==========================================
# TRAIN TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# SCALE POS WEIGHT
# ==========================================

negative_count = (y_train == 0).sum()
positive_count = (y_train == 1).sum()

scale_pos_weight = negative_count / positive_count if positive_count != 0 else 1

print("\nscale_pos_weight:", round(scale_pos_weight, 2))


# ==========================================
# PREPROCESSING
# ==========================================

preprocess = ColumnTransformer(
    transformers=[
        (
            "text",
            TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                max_features=15000,
                ngram_range=(1, 2)
            ),
            "email_text"
        ),
        (
            "num",
            "passthrough",
            FEATURES
        )
    ]
)


# ==========================================
# XGBOOST MODEL
# ==========================================

xgb_model = XGBClassifier(
    n_estimators=700,
    max_depth=6,
    learning_rate=0.03,
    subsample=0.85,
    colsample_bytree=0.85,
    min_child_weight=2,
    gamma=0.1,
    reg_lambda=2,
    scale_pos_weight=scale_pos_weight,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model = Pipeline([
    ("preprocess", preprocess),
    ("xgb", xgb_model)
])


# ==========================================
# TRAINING
# ==========================================

print("\nTraining Hybrid Email/Text XGBoost Model...")
model.fit(X_train, y_train)


# ==========================================
# THRESHOLD TUNING
# ==========================================

probabilities = model.predict_proba(X_test)[:, 1]

best_threshold = 0.45
best_f1 = 0

for threshold in np.arange(0.30, 0.71, 0.01):
    temp_pred = (probabilities >= threshold).astype(int)
    temp_f1 = f1_score(y_test, temp_pred)

    if temp_f1 > best_f1:
        best_f1 = temp_f1
        best_threshold = threshold

best_threshold = round(float(best_threshold), 2)

print("\nBest Threshold:", best_threshold)
print("Best F1 Score:", round(best_f1, 4))


# ==========================================
# FINAL EVALUATION
# ==========================================

pred = (probabilities >= best_threshold).astype(int)

print("\nAccuracy:", round(accuracy_score(y_test, pred) * 100, 2), "%")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, pred))

print("\nClassification Report:")
print(classification_report(y_test, pred, zero_division=0))


# ==========================================
# SAVE MODEL
# ==========================================

os.makedirs("model", exist_ok=True)

joblib.dump(
    {
        "model": model,
        "features": FEATURES,
        "threshold": best_threshold,
        "mode": "hybrid_text_numeric"
    },
    MODEL_PATH
)

print("\nHybrid Email/Text XGBoost Model Saved Successfully")
print("Model Path:", MODEL_PATH)
print("Expected Manual Features:", len(FEATURES))
print("Feature Names:", FEATURES)
print("Threshold:", best_threshold)
print("Mode: hybrid_text_numeric")

print("\nTraining Complete")