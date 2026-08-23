import os
import re
import csv
import hashlib
from pypdf import PdfReader
from docx import Document


# =========================
# CONTENT CHECKING
# =========================

def check_content(text):
    text_lower = text.lower()

    score = 0
    found_keywords = []
    found_links = []
    risk_reasons = []

    suspicious_words = [
        "urgent", "verify", "password", "login", "account",
        "suspended", "blocked", "limited time", "click here",
        "confirm", "update", "security alert", "bank",
        "otp", "cvv", "credit card", "debit card",
        "winner", "prize", "free gift", "claim now",
        "reset your password", "your account will be closed"
    ]

    credential_words = [
        "password", "otp", "pin", "cvv", "credit card",
        "debit card", "bank account", "login details"
    ]

    urgent_words = [
        "urgent", "immediately", "limited time",
        "act now", "warning", "suspended", "blocked"
    ]

    links = re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        text_lower
    )

    for word in suspicious_words:
        if word in text_lower:
            score += 8
            found_keywords.append(word)

    for word in credential_words:
        if word in text_lower:
            score += 10
            risk_reasons.append("Credential request detected")

    for word in urgent_words:
        if word in text_lower:
            score += 8
            risk_reasons.append("Urgent language detected")

    for link in links:
        found_links.append(link)

        if link.startswith("http://"):
            score += 10
            risk_reasons.append("Unsafe HTTP link detected")

        if any(tld in link for tld in [".tk", ".xyz", ".top", ".site", ".online", ".info"]):
            score += 20
            risk_reasons.append("Suspicious domain extension detected")

        if "-" in link:
            score += 5
            risk_reasons.append("Suspicious hyphenated link detected")

    if len(links) > 3:
        score += 10
        risk_reasons.append("Multiple links detected")

    score = min(score, 100)

    if score >= 75:
        prediction = "Phishing Content"
        risk = "High"
    elif score >= 40:
        prediction = "Suspicious Content"
        risk = "Medium"
    else:
        prediction = "Safe Content"
        risk = "Low"

    return {
        "prediction": prediction,
        "score": score,
        "risk": risk,
        "keywords": list(set(found_keywords)),
        "links": found_links,
        "reasons": list(set(risk_reasons))
    }


# =========================
# FILE HASH
# =========================

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            sha256.update(block)

    return sha256.hexdigest()


# =========================
# TEXT EXTRACTION FROM FILE
# =========================

def extract_text_from_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    try:
        if ext == ".txt":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                return file.read()

        elif ext == ".csv":
            text = ""

            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                reader = csv.reader(file)

                for row in reader:
                    text += " ".join(row) + "\n"

            return text

        elif ext == ".pdf":
            text = ""
            reader = PdfReader(file_path)

            for page in reader.pages:
                page_text = page.extract_text()

                if page_text:
                    text += page_text + "\n"

            return text

        elif ext == ".docx":
            doc = Document(file_path)
            text = ""

            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"

            return text

        else:
            return ""

    except Exception as e:
        print("FILE TEXT EXTRACTION ERROR:", e)
        return ""


# =========================
# FILE VERIFICATION
# =========================

def verify_file(file_path, original_filename):
    ext = os.path.splitext(original_filename)[1].lower()
    file_size = os.path.getsize(file_path)
    file_size_mb = round(file_size / (1024 * 1024), 2)

    score = 0
    reasons = []

    allowed_extensions = [
        ".txt", ".pdf", ".docx", ".csv"
    ]

    dangerous_extensions = [
        ".exe", ".bat", ".cmd", ".scr", ".js", ".vbs",
        ".msi", ".apk", ".jar", ".ps1", ".dll", ".sh"
    ]

    suspicious_name_words = [
        "invoice", "payment", "urgent", "password",
        "bank", "verify", "login", "update",
        "reward", "gift", "free", "claim"
    ]

    filename_lower = original_filename.lower()

    if ext in dangerous_extensions:
        score += 60
        reasons.append("Dangerous executable file type detected")

    if ext not in allowed_extensions:
        score += 25
        reasons.append("File type is not in allowed verification list")

    if file_size_mb > 10:
        score += 10
        reasons.append("Large file size detected")

    for word in suspicious_name_words:
        if word in filename_lower:
            score += 8
            reasons.append("Suspicious filename keyword detected")
            break

    file_hash = calculate_file_hash(file_path)

    extracted_text = extract_text_from_file(file_path)

    content_result = None

    if extracted_text.strip():
        content_result = check_content(extracted_text)

        if content_result["score"] >= 75:
            score += 30
            reasons.append("Phishing content detected inside file")

        elif content_result["score"] >= 40:
            score += 15
            reasons.append("Suspicious content detected inside file")

    score = min(score, 100)

    if score >= 75:
        prediction = "Unsafe File"
        risk = "High"
    elif score >= 40:
        prediction = "Suspicious File"
        risk = "Medium"
    else:
        prediction = "Verified File"
        risk = "Low"

    return {
        "filename": original_filename,
        "extension": ext,
        "size_mb": file_size_mb,
        "hash": file_hash,
        "prediction": prediction,
        "score": score,
        "risk": risk,
        "reasons": list(set(reasons)),
        "content_result": content_result
    }