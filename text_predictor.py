import joblib
import pandas as pd

from email_feature_extraction import extract_email_features


MODEL_PATH = "model/email_phishing_model.pkl"

model_data = joblib.load(MODEL_PATH)

text_model = model_data["model"]
text_features = model_data["features"]
threshold = model_data.get("threshold", 0.45)
model_mode = model_data.get("mode", "numeric_only")


def get_risk_level(score):
    if score >= 75:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


def predict_text_phishing(text):
    """
    Used for:
    1. Email Detection
    2. Content Scanning
    3. File Verification after text extraction
    """

    if text is None or len(text.strip()) == 0:
        return {
            "prediction": "No Content",
            "threat_score": 0.0,
            "risk_level": "Low"
        }

    features = extract_email_features(text)

    numeric_df = pd.DataFrame([features])
    numeric_df = numeric_df.reindex(columns=text_features, fill_value=0)

    if model_mode == "hybrid_text_numeric":
        input_df = numeric_df.copy()
        input_df.insert(0, "email_text", text)
    else:
        input_df = numeric_df

    probability = text_model.predict_proba(input_df)[0][1]
    threat_score = round(probability * 100, 2)

    prediction = "Phishing" if probability >= threshold else "Legitimate"
    risk_level = get_risk_level(threat_score)

    return {
        "prediction": prediction,
        "threat_score": threat_score,
        "risk_level": risk_level
    }