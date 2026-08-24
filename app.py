from flask import Flask, render_template, request, redirect, session, jsonify, make_response, flash
from jinja2 import TemplateNotFound
from werkzeug.utils import secure_filename

import os
import re
import csv
import io
import hashlib
import zipfile
import secrets
import resend
import time

from datetime import datetime

from dotenv import load_dotenv
from urllib.parse import urlparse

import joblib
import pandas as pd

from feature_extraction import extract_features
from email_feature_extraction import extract_email_features

from db_operations import (
    create_table,
    create_admin_table,
    create_login_history,
    add_admin,
    validate_admin,
    save_login,
    save_scan,
    get_history,
    delete_scan,
    clear_history,
    get_dashboard_stats,
    get_login_history,
    get_admins,
    get_admin_by_id,
    get_admin_by_username,
    update_admin_password,
    reset_admin_password_db,
    delete_admin,
    count_admins,
    clear_login_history
)


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret-key"
)


# ============================================================
# PASSWORD RESET CONFIGURATION
# ============================================================

RESET_EMAIL = os.getenv(
    "RESET_EMAIL",
    "ssraj464@gmail.com"
)

MAIL_USERNAME = os.getenv(
    "MAIL_USERNAME",
    ""
)

MAIL_PASSWORD = os.getenv(
    "MAIL_PASSWORD",
    ""
)

OTP_EXPIRY_SECONDS = 5 * 60
RESET_SESSION_SECONDS = 10 * 60
MAX_OTP_ATTEMPTS = 5


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

UPLOAD_FOLDER = "uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["MAX_CONTENT_LENGTH"] = (
    10 * 1024 * 1024
)


URL_MODEL_PATH = "model/phishing_model.pkl"

EMAIL_MODEL_PATH = (
    "model/email_phishing_model.pkl"
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

create_table()
create_admin_table()
create_login_history()


# ============================================================
# DEFAULT ADMIN
# ============================================================

# Create default admin only when no admin exists.
# This prevents UNIQUE constraint errors whenever
# Flask restarts.

if count_admins() == 0:

    if add_admin("admin", "12345"):
        print("DEFAULT ADMIN CREATED: admin")
    else:
        print("DEFAULT ADMIN CREATION FAILED")

else:

    print("ADMIN ACCOUNT(S) ALREADY EXIST")


# ============================================================
# GLOBAL MODEL VARIABLES
# ============================================================

url_model = None
url_features = []
url_threshold = 0.45

email_model = None
email_features = []
email_threshold = 0.45
email_model_mode = "numeric_only"


# ============================================================
# DEFAULT EMAIL FEATURES
# ============================================================

DEFAULT_EMAIL_FEATURES = [
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


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = [
    "google.com",
    "accounts.google.com",
    "github.com",
    "cmr.edu.in",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
    "paypal.com",
    "linkedin.com",
    "facebook.com",
    "apple.com",
    "netflix.com"
]


# ============================================================
# TRUSTED SENDERS
# ============================================================

TRUSTED_SENDERS = [
    "support@amazon.in",
    "shipment-tracking@amazon.in",
    "security@paypal.com",
    "notifications@linkedin.com",
    "notifications@github.com",
    "noreply@github.com",
    "no-reply@github.com",
    "account-security@microsoft.com",
    "support@microsoft.com",
    "no-reply@google.com",
    "no-reply@accounts.google.com"
]


# ============================================================
# BRAND WORDS
# ============================================================

BRAND_WORDS = [
    "amazon",
    "amaz0n",
    "paypal",
    "paypai",
    "paypa1",
    "paypall",
    "google",
    "g00gle",
    "microsoft",
    "micros0ft",
    "linkedin",
    "github",
    "facebook",
    "apple",
    "netflix"
]


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

SUSPICIOUS_TLDS = (
    ".tk",
    ".xyz",
    ".top",
    ".site",
    ".online",
    ".cf",
    ".ml",
    ".ga",
    ".gq",
    ".info",
    ".org",
    ".net"
)


# ============================================================
# LOAD MACHINE LEARNING MODELS
# ============================================================

def load_models():

    global url_model
    global url_features
    global url_threshold

    global email_model
    global email_features
    global email_threshold
    global email_model_mode

    # --------------------------------------------------------
    # URL MODEL
    # --------------------------------------------------------

    try:

        if os.path.exists(URL_MODEL_PATH):

            loaded_url = joblib.load(
                URL_MODEL_PATH
            )

            if isinstance(loaded_url, dict):

                url_model = loaded_url.get(
                    "model"
                )

                url_features = loaded_url.get(
                    "features",
                    []
                )

                url_threshold = loaded_url.get(
                    "threshold",
                    0.45
                )

            else:

                url_model = loaded_url

                url_features = []

                url_threshold = 0.45

            print(
                "URL MODEL LOADED"
            )

            print(
                "URL MODEL TYPE:",
                type(url_model)
            )

            print(
                "URL FEATURES:",
                len(url_features)
            )

            print(
                "URL THRESHOLD:",
                url_threshold
            )

        else:

            print(
                "URL MODEL FILE NOT FOUND:",
                URL_MODEL_PATH
            )

    except Exception as e:

        print(
            "URL MODEL ERROR:",
            e
        )

    # --------------------------------------------------------
    # EMAIL MODEL
    # --------------------------------------------------------

    try:

        if os.path.exists(
            EMAIL_MODEL_PATH
        ):

            loaded_email = joblib.load(
                EMAIL_MODEL_PATH
            )

            if isinstance(
                loaded_email,
                dict
            ):

                email_model = loaded_email.get(
                    "model"
                )

                email_features = loaded_email.get(
                    "features",
                    DEFAULT_EMAIL_FEATURES
                )

                email_threshold = loaded_email.get(
                    "threshold",
                    0.45
                )

                email_model_mode = loaded_email.get(
                    "mode",
                    "numeric_only"
                )

            else:

                email_model = loaded_email

                email_features = (
                    DEFAULT_EMAIL_FEATURES
                )

                email_threshold = 0.45

                email_model_mode = (
                    "numeric_only"
                )

            print(
                "EMAIL/TEXT MODEL LOADED"
            )

            print(
                "EMAIL MODEL TYPE:",
                type(email_model)
            )

            print(
                "EMAIL FEATURES:",
                len(email_features)
            )

            print(
                "EMAIL THRESHOLD:",
                email_threshold
            )

            print(
                "EMAIL MODE:",
                email_model_mode
            )

        else:

            print(
                "EMAIL MODEL FILE NOT FOUND:",
                EMAIL_MODEL_PATH
            )

    except Exception as e:

        print(
            "EMAIL MODEL ERROR:",
            e
        )


load_models()


# ============================================================
# COMMON HELPERS
# ============================================================

def admin_required():

    return "admin" in session


def safe_float(
    value,
    default=0.0
):

    try:

        return float(value)

    except Exception:

        return default


def risk_from_score(score):

    score = safe_float(
        score
    )

    if score >= 75:

        return "High"

    elif score >= 40:

        return "Medium"

    else:

        return "Low"


def classify_url(score):

    score = safe_float(
        score
    )

    risk = risk_from_score(
        score
    )

    if score >= 75:

        return (
            "Phishing Website",
            risk
        )

    elif score >= 40:

        return (
            "Suspicious Website",
            risk
        )

    else:

        return (
            "Legitimate Website",
            risk
        )


def classify_text(
    score,
    category="email"
):

    score = safe_float(
        score
    )

    risk = risk_from_score(
        score
    )

    labels = {

        "email": (
            "Phishing Email",
            "Suspicious Email",
            "Legitimate Email"
        ),

        "content": (
            "Phishing Content",
            "Suspicious Content",
            "Legitimate Content"
        ),

        "file": (
            "Phishing File",
            "Suspicious File",
            "Legitimate File"
        )
    }

    phishing_label, suspicious_label, legitimate_label = labels.get(
        category,
        labels["email"]
    )

    if score >= 75:

        return (
            phishing_label,
            risk
        )

    elif score >= 40:

        return (
            suspicious_label,
            risk
        )

    else:

        return (
            legitimate_label,
            risk
        )


def normalize_text_result_category(
    result,
    category
):

    score = safe_float(
        result.get(
            "score",
            0.0
        )
    )

    prediction, risk = classify_text(
        score,
        category=category
    )

    result["prediction"] = prediction
    result["risk"] = risk

    return result


def domain_matches(
    domain,
    domain_list
):

    domain = str(
        domain
    ).lower().strip()

    return any(
        domain == trusted_domain
        or domain.endswith(
            "." + trusted_domain
        )
        for trusted_domain in domain_list
    )


def clean_url_text(url):

    url = str(
        url
    ).strip().strip(
        ".,);]}>"
    )

    if url.startswith("www."):

        url = (
            "https://" + url
        )

    return url


def make_safe_upload_name(
    filename
):

    clean_name = secure_filename(
        filename
    )

    if not clean_name:

        clean_name = "uploaded_file"

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    return (
        f"{timestamp}_{clean_name}"
    )


def get_file_hash(
    file_path
):

    sha256 = hashlib.sha256()

    with open(
        file_path,
        "rb"
    ) as file:

        for block in iter(
            lambda: file.read(4096),
            b""
        ):

            sha256.update(
                block
            )

    return sha256.hexdigest()


# ============================================================
# URL HELPERS
# ============================================================

def valid_url(text):

    try:
        text = str(text).strip()

        if not text:
            return False

        url = normalize_url(text)
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.netloc:
            return False

        if any(char.isspace() for char in url):
            return False

        if not parsed.hostname:
            return False

        return True

    except Exception:
        return False

def normalize_url(url):

    url = str(
        url
    ).strip()

    if not url.startswith(
        ("http://", "https://")
    ):

        url = (
            "https://" + url
        )

    return url


def get_domain(url):

    return urlparse(
        normalize_url(url)
    ).netloc.lower()


def whitelist_safe_domain(url):

    domain = get_domain(
        url
    )

    return domain_matches(
        domain,
        TRUSTED_DOMAINS
    )


def phishing_rule_score(url):

    u = normalize_url(url).lower()

    try:
        parsed = urlparse(u)
        domain = (parsed.hostname or "").lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return 100

    score = 0

    # Strong deceptive URL structure.
    if "@" in netloc:
        score += 50

    # IPv4 host instead of a normal domain.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
        score += 40

    if parsed.scheme == "http":
        score += 10

    high_risk_words = [
        "login", "signin", "sign-in", "verify", "verification",
        "password", "credential", "account", "security", "secure",
        "update", "confirm", "reset", "bank", "billing", "payment",
        "wallet", "alert", "support"
    ]

    word_hits = sum(
        1 for word in high_risk_words if word in u
    )

    score += min(word_hits * 8, 40)

    if domain.endswith(SUSPICIOUS_TLDS):
        score += 30

    domain_parts = domain.split(".")

    if len(domain_parts) >= 4:
        score += 15

    if len(domain_parts) >= 5:
        score += 15

    if "-" in domain:
        score += 10

    if not domain_matches(domain, TRUSTED_DOMAINS):
        for brand in BRAND_WORDS:
            if brand in domain:
                score += 35
                break

    suspicious_paths = [
        "/login", "/signin", "/sign-in", "/verify",
        "/verification", "/password", "/reset",
        "/account", "/secure", "/security",
        "/billing", "/payment"
    ]

    if any(suspicious_path in path for suspicious_path in suspicious_paths):
        score += 15

    if len(u) > 100:
        score += 10

    if len(u) > 180:
        score += 10

    if parsed.query:
        score += 5

    return min(score, 100)

def make_url_input(
    features
):

    if isinstance(
        features,
        dict
    ):

        if url_features:

            return pd.DataFrame(
                [features]
            ).reindex(
                columns=url_features,
                fill_value=0
            )

        return pd.DataFrame(
            [features]
        )

    if url_features:

        if len(features) != len(
            url_features
        ):

            raise Exception(
                f"URL feature mismatch: model expects "
                f"{len(url_features)}, extractor gives "
                f"{len(features)}"
            )

        return pd.DataFrame(
            [features],
            columns=url_features
        )

    return [features]


# ============================================================
# EMAIL / TEXT HELPERS
# ============================================================

def clean_sender_input(text):

    t = str(
        text
    ).lower().strip()

    t = t.replace(
        "mailto:",
        ""
    )

    return t.strip()


def extract_sender_email(text):

    t = clean_sender_input(
        text
    )

    match = re.search(
        r'from:\s*<?([\w\.-]+@[\w\.-]+\.[a-z]{2,})>?',
        t
    )

    if match:

        return match.group(1)

    match = re.search(
        r'\b[\w\.-]+@[\w\.-]+\.[a-z]{2,}\b',
        t
    )

    if match:

        return match.group(0)

    return ""


def is_sender_only_input(text):

    t = clean_sender_input(
        text
    )

    return bool(
        re.fullmatch(
            r'(from:\s*)?<?[\w\.-]+@[\w\.-]+\.[a-z]{2,}>?',
            t
        )
    )


def extract_links(text):

    return re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        str(text).lower()
    )


def extract_suspicious_keywords(
    text
):

    keywords = [

        "urgent",
        "verify",
        "verification",
        "password",
        "otp",
        "cvv",
        "login",
        "account",
        "security",
        "suspended",
        "blocked",
        "winner",
        "reward",
        "claim",
        "immediately",
        "restricted",
        "confirm",
        "locked",
        "update",
        "warning",
        "alert",
        "expire",
        "expires",
        "suspicious activity",
        "unusual login"
    ]

    lower_text = str(
        text
    ).lower()

    return [
        word
        for word in keywords
        if word in lower_text
    ]


def is_source_code_content(
    text
):

    t = str(
        text
    ).strip()

    tl = t.lower()

    if len(t) < 80:

        return False

    code_markers = [

        "from flask import",
        "import os",
        "import re",
        "import csv",
        "import hashlib",
        "def ",
        "class ",
        "@app.route",
        "render_template(",
        "request.form",
        "session[",
        "joblib.load",
        "pd.dataframe",
        "try:",
        "except exception",
        "if __name__"
    ]

    hits = sum(
        1
        for marker in code_markers
        if marker in tl
    )

    return hits >= 3


def is_benign_security_notice(
    text
):

    t = str(
        text
    ).lower()

    benign_phrases = [

        "if this was you, no action is required",
        "no action is required",
        "from a recognized device",
        "from a trusted device",
        "from your account settings",
        "you can review your recent account activity from your account settings",
        "thank you for helping us keep your account secure"
    ]

    hard_phishing_terms = [

        "click here",
        "click the link",
        "click below",
        "verify your identity",
        "verify your account",
        "verify your password",
        "password will expire",
        "account will be suspended",
        "suspended within",
        "enter your details",
        "update your password",
        "reset password",
        "otp",
        "cvv",
        "credit card",
        "bank details",
        "http://",
        "https://",
        "www."
    ]

    has_benign = any(
        phrase in t
        for phrase in benign_phrases
    )

    has_hard_phishing = any(
        term in t
        for term in hard_phishing_terms
    )

    return (
        has_benign
        and not has_hard_phishing
    )


def email_features_to_dict(
    text
):

    raw_features = extract_email_features(
        text
    )

    if isinstance(
        raw_features,
        dict
    ):

        return {
            feature: raw_features.get(
                feature,
                0
            )
            for feature in DEFAULT_EMAIL_FEATURES
        }

    if hasattr(
        raw_features,
        "to_dict"
    ):

        raw_dict = raw_features.to_dict()

        return {
            feature: raw_dict.get(
                feature,
                0
            )
            for feature in DEFAULT_EMAIL_FEATURES
        }

    try:

        return dict(
            zip(
                DEFAULT_EMAIL_FEATURES,
                list(raw_features)
            )
        )

    except Exception:

        return {
            feature: 0
            for feature in DEFAULT_EMAIL_FEATURES
        }


def calculate_email_indicators(
    text,
    feature_dict=None
):

    if feature_dict is None:

        feature_dict = {}

    t = str(
        text
    ).lower()

    suspicious_links = int(
        safe_float(
            feature_dict.get(
                "links",
                0
            )
        )
        +
        safe_float(
            feature_dict.get(
                "short_links",
                0
            )
        )
        +
        safe_float(
            feature_dict.get(
                "ip_links",
                0
            )
        )
    )

    urls = extract_links(
        t
    )

    shorteners = [

        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "rb.gy",
        "ow.ly",
        "is.gd",
        "cutt.ly"
    ]

    for url in urls:

        clean_url = clean_url_text(
            url
        )

        domain = urlparse(
            clean_url
        ).netloc.lower()

        if clean_url.startswith(
            "http://"
        ):

            suspicious_links += 1

        if any(
            short in domain
            for short in shorteners
        ):

            suspicious_links += 1

        if "-" in domain:

            suspicious_links += 1

        if domain.endswith(
            SUSPICIOUS_TLDS
        ):

            suspicious_links += 1

        if any(
            brand in domain
            for brand in BRAND_WORDS
        ):

            if not domain_matches(
                domain,
                TRUSTED_DOMAINS
            ):

                suspicious_links += 1

    urgent_terms = [

        "urgent",
        "immediately",
        "within 24 hours",
        "within 12 hours",
        "expire",
        "expires",
        "suspended",
        "blocked",
        "locked",
        "warning",
        "alert",
        "avoid losing access",
        "action required",
        "suspicious activity",
        "access warning",
        "delivery failed",
        "security check required",
        "unusual login attempt"
    ]

    credential_terms = [

        "password",
        "verify",
        "verification",
        "confirm",
        "account information",
        "account details",
        "account activity",
        "login",
        "signin",
        "sign in",
        "otp",
        "cvv",
        "credit card",
        "bank details",
        "delivery details",
        "personal details",
        "reset password",
        "click the link",
        "click below",
        "enter your details",
        "update your password",
        "review your account information"
    ]

    urgent_words = int(
        safe_float(
            feature_dict.get(
                "urgent_words",
                0
            )
        )
    )

    credential_words = int(
        safe_float(
            feature_dict.get(
                "credential_words",
                0
            )
        )
    )

    for word in urgent_terms:

        if word in t:

            urgent_words += 1

    for word in credential_terms:

        if word in t:

            credential_words += 1

    fake_sender = int(
        safe_float(
            feature_dict.get(
                "fake_sender",
                0
            )
        )
    )

    sender = extract_sender_email(
        text
    )

    if sender:

        sender = sender.lower().strip()

        sender_domain = sender.split("@")[-1]

        free_mail_domains = [

            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "hotmail.com",
            "protonmail.com"
        ]

        if (
            sender not in TRUSTED_SENDERS
            and not domain_matches(
                sender_domain,
                TRUSTED_DOMAINS
            )
        ):

            if any(
                brand in sender
                for brand in BRAND_WORDS
            ):

                fake_sender = 1

            if (
                sender_domain in free_mail_domains
                and any(
                    brand in sender
                    for brand in BRAND_WORDS
                )
            ):

                fake_sender = 1

            if sender_domain.endswith(
                SUSPICIOUS_TLDS
            ):

                fake_sender = 1

            if (
                "-" in sender_domain
                and any(
                    brand in sender_domain
                    for brand in BRAND_WORDS
                )
            ):

                fake_sender = 1

            if any(
                word in sender
                for word in [
                    "security",
                    "alert",
                    "verify",
                    "account",
                    "delivery",
                    "notify"
                ]
            ):

                fake_sender = 1

    return {

        "suspicious_links":
            int(suspicious_links),

        "urgent_words":
            int(urgent_words),

        "credential_words":
            int(credential_words),

        "fake_sender":
            int(fake_sender)
    }


def email_rule_score(
    text
):

    t = str(
        text
    ).lower()

    score = 0

    suspicious_words = [

        "verify",
        "password",
        "suspended",
        "urgent",
        "immediately",
        "login",
        "account",
        "security",
        "alert",
        "blocked",
        "update",
        "confirm",
        "otp",
        "cvv",
        "credit card",
        "claim",
        "winner",
        "restricted",
        "locked",
        "warning",
        "expire"
    ]

    for word in suspicious_words:

        if word in t:

            score += 8

    for url in extract_links(t):

        clean_url = clean_url_text(
            url
        )

        domain = urlparse(
            clean_url
        ).netloc.lower()

        if clean_url.startswith(
            "http://"
        ):

            score += 10

        if "-" in domain:

            score += 10

        if domain.endswith(
            SUSPICIOUS_TLDS
        ):

            score += 25

        if any(
            brand in domain
            for brand in BRAND_WORDS
        ):

            if not domain_matches(
                domain,
                TRUSTED_DOMAINS
            ):

                score += 30

    return min(
        score,
        100
    )


def build_reasons(
    indicators,
    keywords,
    links,
    ml_score,
    rule_score
):

    reasons = []

    if ml_score >= (
        email_threshold * 100
    ):

        reasons.append(
            "AI text model detected phishing-like language"
        )

    if rule_score >= 40:

        reasons.append(
            "Rule-based phishing indicators detected"
        )

    if indicators.get(
        "suspicious_links",
        0
    ) > 0:

        reasons.append(
            "Suspicious link pattern found"
        )

    if indicators.get(
        "urgent_words",
        0
    ) > 0:

        reasons.append(
            "Urgency words found"
        )

    if indicators.get(
        "credential_words",
        0
    ) > 0:

        reasons.append(
            "Credential-related words found"
        )

    if indicators.get(
        "fake_sender",
        0
    ) > 0:

        reasons.append(
            "Possible fake sender indicator found"
        )

    if keywords:

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(
                keywords[:8]
            )
        )

    if links:

        reasons.append(
            f"Total links detected: {len(links)}"
        )

    if not reasons:

        reasons.append(
            "No strong phishing indicators detected"
        )

    return reasons


def sender_only_decision(
    text
):

    sender = extract_sender_email(
        text
    )

    if not sender:

        return None

    sender = sender.lower().strip()

    sender_domain = sender.split(
        "@"
    )[-1]

    indicators = {

        "suspicious_links": 0,
        "urgent_words": 0,
        "credential_words": 0,
        "fake_sender": 0
    }

    suspicious_words = [

        "verify",
        "verification",
        "login",
        "update",
        "alert",
        "security",
        "account",
        "support",
        "check",
        "confirm",
        "secure",
        "reset",
        "warning",
        "blocked",
        "suspended"
    ]

    finance_words = [

        "bank",
        "finance",
        "loan",
        "payment",
        "wallet",
        "card"
    ]

    free_mail_domains = [

        "gmail.com",
        "outlook.com",
        "yahoo.com",
        "hotmail.com",
        "protonmail.com"
    ]

    if (
        sender in TRUSTED_SENDERS
        or domain_matches(
            sender_domain,
            TRUSTED_DOMAINS
        )
    ):

        return {

            "prediction":
                "Legitimate Email",

            "score":
                5.0,

            "risk":
                "Low",

            "indicators":
                indicators,

            "reasons":
                ["Trusted sender/domain"]
        }

    has_brand = any(
        brand in sender
        for brand in BRAND_WORDS
    )

    has_finance = any(
        word in sender
        for word in finance_words
    )

    has_suspicious = any(
        word in sender
        for word in suspicious_words
    )

    if (
        sender_domain in free_mail_domains
        and has_brand
    ):

        indicators["fake_sender"] = 1

        return {

            "prediction":
                "Phishing Email",

            "score":
                85.0,

            "risk":
                "High",

            "indicators":
                indicators,

            "reasons":
                [
                    "Brand name used from free email provider"
                ]
        }

    if (
        has_brand
        and not domain_matches(
            sender_domain,
            TRUSTED_DOMAINS
        )
    ):

        indicators["fake_sender"] = 1

        return {

            "prediction":
                "Phishing Email",

            "score":
                90.0,

            "risk":
                "High",

            "indicators":
                indicators,

            "reasons":
                [
                    "Famous brand impersonation detected"
                ]
        }

    if (
        has_finance
        and has_suspicious
    ):

        indicators["fake_sender"] = 1

        return {

            "prediction":
                "Suspicious Email",

            "score":
                65.0,

            "risk":
                "Medium",

            "indicators":
                indicators,

            "reasons":
                [
                    "Generic finance/security sender pattern detected"
                ]
        }

    if (
        sender_domain.endswith(
            SUSPICIOUS_TLDS
        )
        and has_suspicious
    ):

        indicators["fake_sender"] = 1

        return {

            "prediction":
                "Suspicious Email",

            "score":
                60.0,

            "risk":
                "Medium",

            "indicators":
                indicators,

            "reasons":
                [
                    "Suspicious domain extension and sender wording"
                ]
        }

    if has_suspicious:

        return {

            "prediction":
                "Suspicious Email",

            "score":
                45.0,

            "risk":
                "Medium",

            "indicators":
                indicators,

            "reasons":
                [
                    "Suspicious words found in sender address"
                ]
        }

    return {

        "prediction":
            "Legitimate Email",

        "score":
            20.0,

        "risk":
            "Low",

        "indicators":
            indicators,

        "reasons":
            [
                "No strong sender-only phishing indicator found"
            ]
    }


def predict_text_phishing(
    text,
    category="email"
):
    """
    Predict phishing risk for email/content text.

    IMPORTANT:
    - The ML model score is treated as a signal, not as the final truth.
    - A very high ML score with ZERO independent phishing indicators is
      capped to avoid false HIGH results caused by model calibration.
    - Strong corroborating indicators can still produce HIGH risk.
    """

    text = str(text or "").strip()

    # --------------------------------------------------------
    # EMPTY TEXT
    # --------------------------------------------------------

    if not text:
        prediction, risk = classify_text(
            0.0,
            category=category
        )

        return {
            "prediction": prediction,
            "score": 0.0,
            "risk": risk,
            "indicators": {
                "suspicious_links": 0,
                "urgent_words": 0,
                "credential_words": 0,
                "fake_sender": 0
            },
            "keywords": [],
            "links": [],
            "reasons": ["No text content found"],
            "model_score": 0.0,
            "rule_score": 0.0
        }

    # --------------------------------------------------------
    # SOURCE CODE
    # --------------------------------------------------------

    if is_source_code_content(text):
        prediction, risk = classify_text(
            5.0,
            category=category
        )

        return {
            "prediction": prediction,
            "score": 5.0,
            "risk": risk,
            "indicators": {
                "suspicious_links": 0,
                "urgent_words": 0,
                "credential_words": 0,
                "fake_sender": 0
            },
            "keywords": [],
            "links": [],
            "reasons": [
                "Programming/source code content detected, not phishing message content"
            ],
            "model_score": 5.0,
            "rule_score": 5.0
        }

    # --------------------------------------------------------
    # BASIC ANALYSIS
    # --------------------------------------------------------

    sender = extract_sender_email(text)
    sender_domain = (
        sender.split("@")[-1].lower()
        if sender
        else ""
    )

    sender_is_trusted = bool(sender) and (
        sender.lower() in TRUSTED_SENDERS
        or domain_matches(
            sender_domain,
            TRUSTED_DOMAINS
        )
    )

    links = extract_links(text)

    # Determine whether any link is outside the trusted list.
    has_untrusted_link = False

    for link in links:
        clean_link = clean_url_text(link)

        link_domain = urlparse(
            clean_link
        ).netloc.lower()

        if (
            link_domain
            and not domain_matches(
                link_domain,
                TRUSTED_DOMAINS
            )
        ):
            has_untrusted_link = True
            break

    # --------------------------------------------------------
    # TRUSTED SENDER
    # --------------------------------------------------------

    if sender_is_trusted and not has_untrusted_link:
        prediction, risk = classify_text(
            5.0,
            category=category
        )

        return {
            "prediction": prediction,
            "score": 5.0,
            "risk": risk,
            "indicators": {
                "suspicious_links": 0,
                "urgent_words": 0,
                "credential_words": 0,
                "fake_sender": 0
            },
            "keywords": [],
            "links": links,
            "reasons": [
                "Trusted sender/domain and no suspicious external link found"
            ],
            "model_score": 5.0,
            "rule_score": 5.0
        }

    # --------------------------------------------------------
    # FEATURES / INDICATORS
    # --------------------------------------------------------

    feature_dict = email_features_to_dict(text)

    indicators = calculate_email_indicators(
        text,
        feature_dict
    )

    keywords = extract_suspicious_keywords(text)
    text_lower = text.lower()

    # Strong credential-theft phrases.
    strong_credential_words = [
        "verify your password",
        "verify password",
        "password",
        "otp",
        "cvv",
        "credit card",
        "bank details",
        "login link",
        "enter your details",
        "update your password",
        "reset password",
        "click the link",
        "click below",
        "enter your otp",
        "enter otp"
    ]

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    unofficial_brand_sender = (
        bool(sender)
        and not sender_is_trusted
        and (
            any(
                brand in sender.lower()
                for brand in BRAND_WORDS
            )
            or any(
                brand in sender_domain
                for brand in BRAND_WORDS
            )
        )
    )

    if (
        unofficial_brand_sender
        and (
            has_untrusted_link
            or any(
                word in text_lower
                for word in strong_credential_words
            )
        )
    ):
        prediction, risk = classify_text(
            90.0,
            category=category
        )

        return {
            "prediction": prediction,
            "score": 90.0,
            "risk": risk,
            "indicators": indicators,
            "keywords": keywords,
            "links": links,
            "reasons": [
                "Unofficial brand sender detected",
                "Strong phishing signal found"
            ],
            "model_score": 90.0,
            "rule_score": 90.0
        }

    # --------------------------------------------------------
    # ML MODEL INPUT
    # --------------------------------------------------------

    if email_model is None:
        raise Exception(
            "Email/Text model not loaded"
        )

    model_features = (
        email_features
        if email_features
        else DEFAULT_EMAIL_FEATURES
    )

    numeric_df = pd.DataFrame(
        [feature_dict]
    )

    numeric_df = numeric_df.reindex(
        columns=model_features,
        fill_value=0
    )

    if email_model_mode == "hybrid_text_numeric":
        input_data = numeric_df.copy()
        input_data.insert(
            0,
            "email_text",
            text
        )
    else:
        input_data = numeric_df

    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

    probability = email_model.predict_proba(
        input_data
    )[0][1]

    ml_score = round(
        float(probability) * 100,
        2
    )

    # --------------------------------------------------------
    # RULE SCORE
    # --------------------------------------------------------

    rule_score = email_rule_score(text)

    if indicators["fake_sender"] == 1:
        rule_score = max(
            rule_score,
            80
        )

    if (
        indicators["suspicious_links"] > 0
        and (
            indicators["urgent_words"] > 0
            or indicators["credential_words"] > 0
        )
    ):
        rule_score = max(
            rule_score,
            85
        )

    # --------------------------------------------------------
    # FINAL SCORE / CALIBRATION GUARDRAIL
    # --------------------------------------------------------
    #
    # The old code used:
    #
    #     max(ml_score, rule_score)
    #
    # That means a badly calibrated ML probability such as 99.52%
    # automatically became HIGH even when every security indicator
    # was zero.
    #
    # The new logic requires corroborating evidence before allowing
    # a very high ML score to become HIGH.
    # --------------------------------------------------------

    suspicious_links = int(
        indicators.get("suspicious_links", 0)
    )

    urgent_words = int(
        indicators.get("urgent_words", 0)
    )

    credential_words = int(
        indicators.get("credential_words", 0)
    )

    fake_sender = int(
        indicators.get("fake_sender", 0)
    )

    indicator_count = (
        suspicious_links
        + urgent_words
        + credential_words
        + fake_sender
    )

    keyword_count = len(keywords)
    link_count = len(links)

    strong_signal = (
        fake_sender > 0
        or credential_words >= 2
        or (
            suspicious_links > 0
            and (
                urgent_words > 0
                or credential_words > 0
            )
        )
        or (
            keyword_count >= 3
            and (
                urgent_words > 0
                or credential_words > 0
            )
        )
    )

    moderate_signal = (
        indicator_count > 0
        or keyword_count > 0
        or link_count > 0
        or rule_score >= 20
    )

    if strong_signal:
        # Strong independent evidence: allow the ML model to contribute.
        score = round(
            max(
                rule_score,
                (0.70 * ml_score) + (0.30 * rule_score)
            ),
            2
        )

        # Strong phishing indicators should be able to reach HIGH.
        if rule_score >= 80:
            score = max(
                score,
                rule_score
            )

    elif moderate_signal:
        # Some suspicious evidence exists, but not enough to blindly
        # trust an extreme ML probability.
        score = round(
            max(
                rule_score,
                min(
                    69.0,
                    (0.55 * ml_score) + (0.45 * rule_score)
                )
            ),
            2
        )

    else:
        # No links, no urgency, no credential request, no fake sender,
        # and no suspicious keywords.
        #
        # This prevents a poorly calibrated text model from turning
        # ordinary messages into HIGH risk.
        score = round(
            min(
                25.0,
                max(
                    5.0,
                    (0.20 * ml_score) + (0.80 * rule_score)
                )
            ),
            2
        )

    # --------------------------------------------------------
    # FINAL CLASSIFICATION
    # --------------------------------------------------------

    prediction, risk = classify_text(
        score,
        category=category
    )

    reasons = []

    if strong_signal:
        if ml_score >= email_threshold * 100:
            reasons.append(
                "AI text model detected phishing-like language"
            )

    if rule_score >= 40:
        reasons.append(
            "Rule-based phishing indicators detected"
        )

    if suspicious_links > 0:
        reasons.append(
            "Suspicious link pattern found"
        )

    if urgent_words > 0:
        reasons.append(
            "Urgency words found"
        )

    if credential_words > 0:
        reasons.append(
            "Credential-related words found"
        )

    if fake_sender > 0:
        reasons.append(
            "Possible fake sender indicator found"
        )

    if keywords:
        reasons.append(
            "Suspicious keywords: "
            + ", ".join(keywords[:8])
        )

    if links:
        reasons.append(
            f"Total links detected: {len(links)}"
        )

    if not reasons:
        reasons.append(
            "No strong phishing indicators detected"
        )

    return {
        "prediction": prediction,
        "score": score,
        "risk": risk,
        "indicators": indicators,
        "keywords": keywords,
        "links": links,
        "reasons": reasons,
        "model_score": ml_score,
        "rule_score": rule_score
    }


# ============================================================
# FILE HELPERS
# ============================================================

def extension_rule_score(
    extension
):

    extension = extension.lower()

    high_risk_extensions = {

        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".vbs",
        ".js",
        ".ps1",
        ".jar",
        ".msi",
        ".apk",
        ".com"
    }

    medium_risk_extensions = {

        ".docm",
        ".xlsm",
        ".pptm",
        ".html",
        ".htm",
        ".zip",
        ".rar",
        ".7z"
    }

    if extension in high_risk_extensions:

        return 85

    if extension in medium_risk_extensions:

        return 60

    return 10


def extract_text_from_file(
    file_path
):

    extension = os.path.splitext(
        file_path
    )[1].lower()

    try:

        if extension in {
            ".txt",
            ".csv",
            ".html",
            ".htm",
            ".json",
            ".xml",
            ".md",
            ".py"
        }:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                return file.read()

        if extension == ".pdf":

            try:

                from PyPDF2 import PdfReader

            except Exception:

                return ""

            reader = PdfReader(
                file_path
            )

            text = ""

            for page in reader.pages:

                page_text = (
                    page.extract_text()
                )

                if page_text:

                    text += (
                        page_text + "\n"
                    )

            return text

        if extension == ".docx":

            try:

                from docx import Document

            except Exception:

                return ""

            document = Document(
                file_path
            )

            return "\n".join(
                paragraph.text
                for paragraph in document.paragraphs
            )

        if extension in {
            ".xlsx",
            ".xls"
        }:

            try:

                excel_data = pd.read_excel(
                    file_path,
                    sheet_name=None
                )

            except Exception:

                return ""

            text_parts = []

            for (
                sheet_name,
                sheet_df
            ) in excel_data.items():

                text_parts.append(
                    f"Sheet: {sheet_name}"
                )

                text_parts.append(
                    sheet_df.astype(
                        str
                    ).head(
                        500
                    ).to_string(
                        index=False
                    )
                )

            return "\n".join(
                text_parts
            )

    except Exception as e:

        print(
            "FILE TEXT EXTRACTION ERROR:",
            e
        )

    return ""


def inspect_zip_file(
    file_path
):

    high_risk_extensions = {

        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".vbs",
        ".js",
        ".ps1",
        ".jar",
        ".msi",
        ".apk",
        ".com"
    }

    medium_risk_extensions = {

        ".html",
        ".htm",
        ".docm",
        ".xlsm",
        ".pptm"
    }

    readable_extensions = {

        ".txt",
        ".csv",
        ".html",
        ".htm",
        ".json",
        ".xml",
        ".md",
        ".py"
    }

    collected_text = []

    max_read_bytes = 200000

    try:

        if not zipfile.is_zipfile(
            file_path
        ):

            return {

                "score":
                    60.0,

                "reason":
                    "File has ZIP extension but is not a valid ZIP archive",

                "extracted_text":
                    ""
            }

        with zipfile.ZipFile(
            file_path,
            "r"
        ) as zip_ref:

            file_infos = (
                zip_ref.infolist()
            )

            if not file_infos:

                return {

                    "score":
                        40.0,

                    "reason":
                        "Empty ZIP archive detected",

                    "extracted_text":
                        ""
                }

            if len(file_infos) > 100:

                return {

                    "score":
                        75.0,

                    "reason":
                        "ZIP contains too many files and may be suspicious",

                    "extracted_text":
                        ""
                }

            for info in file_infos:

                inner_name = (
                    info.filename
                )

                inner_ext = os.path.splitext(
                    inner_name
                )[1].lower()

                if info.file_size > (
                    5 * 1024 * 1024
                ):

                    return {

                        "score":
                            75.0,

                        "reason":
                            f"ZIP contains unusually large file: {inner_name}",

                        "extracted_text":
                            ""
                    }

                if inner_ext in high_risk_extensions:

                    return {

                        "score":
                            90.0,

                        "reason":
                            f"ZIP contains high-risk executable/script file: {inner_name}",

                        "extracted_text":
                            ""
                    }

                if inner_ext in medium_risk_extensions:

                    return {

                        "score":
                            65.0,

                        "reason":
                            f"ZIP contains active-content file: {inner_name}",

                        "extracted_text":
                            ""
                    }

                if inner_ext in readable_extensions:

                    try:

                        with zip_ref.open(
                            info,
                            "r"
                        ) as inner_file:

                            raw = inner_file.read(
                                max_read_bytes
                            )

                            text = raw.decode(
                                "utf-8",
                                errors="ignore"
                            )

                            if text.strip():

                                collected_text.append(
                                    f"\n--- File inside ZIP: {inner_name} ---\n{text}"
                                )

                    except Exception:

                        pass

            extracted_text = (
                "\n".join(
                    collected_text
                ).strip()
            )

            if extracted_text:

                return {

                    "score":
                        60.0,

                    "reason":
                        "ZIP archive inspected and readable text was found",

                    "extracted_text":
                        extracted_text
                }

            return {

                "score":
                    60.0,

                "reason":
                    "Compressed archive file detected; contents should be handled carefully",

                "extracted_text":
                    ""
            }

    except Exception as e:

        print(
            "ZIP INSPECTION ERROR:",
            e
        )

        return {

            "score":
                60.0,

            "reason":
                "Unable to inspect ZIP archive safely",

            "extracted_text":
                ""
        }


def verify_uploaded_file(
    file_path,
    original_filename
):

    extension = os.path.splitext(
        original_filename
    )[1].lower()

    size_mb = round(
        os.path.getsize(
            file_path
        ) / (1024 * 1024),
        2
    )

    file_hash = get_file_hash(
        file_path
    )

    # --------------------------------------------------------
    # ZIP
    # --------------------------------------------------------

    if extension == ".zip":

        zip_result = inspect_zip_file(
            file_path
        )

        zip_score = float(
            zip_result.get(
                "score",
                60.0
            )
        )

        zip_reason = zip_result.get(
            "reason",
            "Compressed archive file detected"
        )

        zip_text = zip_result.get(
            "extracted_text",
            ""
        )

        if zip_text.strip():

            content_result = predict_text_phishing(
                zip_text,
                category="file"
            )

            content_result = normalize_text_result_category(
                content_result,
                "file"
            )

            final_score = max(
                zip_score,
                safe_float(
                    content_result["score"]
                )
            )

            prediction, risk = classify_text(
                final_score,
                category="file"
            )

            reasons = [
                zip_reason
            ] + content_result.get(
                "reasons",
                []
            )

            return {

                "filename":
                    original_filename,

                "extension":
                    extension,

                "size_mb":
                    size_mb,

                "hash":
                    file_hash,

                "prediction":
                    prediction,

                "score":
                    final_score,

                "risk":
                    risk,

                "reasons":
                    reasons,

                "content_result":
                    content_result,

                "extracted_text":
                    zip_text[:1000]
            }

        prediction, risk = classify_text(
            zip_score,
            category="file"
        )

        return {

            "filename":
                original_filename,

            "extension":
                extension,

            "size_mb":
                size_mb,

            "hash":
                file_hash,

            "prediction":
                prediction,

            "score":
                zip_score,

            "risk":
                risk,

            "reasons":
                [zip_reason],

            "content_result":
                None,

            "extracted_text":
                ""
        }

    # --------------------------------------------------------
    # OTHER FILES
    # --------------------------------------------------------

    extracted_text = extract_text_from_file(
        file_path
    )

    if extracted_text.strip():

        content_result = predict_text_phishing(
            extracted_text,
            category="file"
        )

        content_result = normalize_text_result_category(
            content_result,
            "file"
        )

        return {

            "filename":
                original_filename,

            "extension":
                extension,

            "size_mb":
                size_mb,

            "hash":
                file_hash,

            "prediction":
                content_result["prediction"],

            "score":
                content_result["score"],

            "risk":
                content_result["risk"],

            "reasons":
                content_result.get(
                    "reasons",
                    []
                ),

            "content_result":
                content_result,

            "extracted_text":
                extracted_text[:1000]
        }

    # --------------------------------------------------------
    # EXTENSION BASED SCORING
    # --------------------------------------------------------

    ext_score = extension_rule_score(
        extension
    )

    prediction, risk = classify_text(
        ext_score,
        category="file"
    )

    if ext_score >= 75:

        reasons = [
            "High-risk executable or script file extension"
        ]

    elif ext_score >= 40:

        reasons = [
            "File extension can contain active content or scripts"
        ]

    else:

        reasons = [
            "No readable text found; file checked using metadata only"
        ]

    return {

        "filename":
            original_filename,

        "extension":
            extension,

        "size_mb":
            size_mb,

        "hash":
            file_hash,

        "prediction":
            prediction,

        "score":
            float(ext_score),

        "risk":
            risk,

        "reasons":
            reasons,

        "content_result":
            None,

        "extracted_text":
            ""
    }


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        if validate_admin(
            username,
            password
        ):

            session["admin"] = username

            save_login(
                username
            )

            return redirect(
                "/history"
            )

        error = "Invalid Login"

    return render_template(
        "login.html",
        error=error
    )


# ============================================================
# PASSWORD RESET EMAIL - RESEND
# ============================================================

def send_reset_otp(otp):

    """
    Send password-reset OTP using Resend HTTPS API.

    This replaces Gmail SMTP because Render Free
    blocks outbound SMTP ports 25, 465 and 587.
    """

    resend_api_key = os.getenv(
        "RESEND_API_KEY"
    )

    reset_email = os.getenv(
        "RESET_EMAIL"
    )

    if not resend_api_key:

        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    if not reset_email:

        raise RuntimeError(
            "RESET_EMAIL is not configured."
        )

    resend.api_key = resend_api_key

    params = {

        "from":
            "AI Phishing Detection <onboarding@resend.dev>",

        "to":
            [reset_email],

        "subject":
            "AI Phishing Detection - Admin Password Reset OTP",

        "text":
            f"""AI Phishing Detection System

            Your admin password reset OTP is: {otp}

            This OTP is valid for 5 minutes and can be used only once.

            If you did not request a password reset, ignore this email.

            Regards,
            AI Phishing Detection System
            """
    }

    try:

        email = resend.Emails.send(
            params
        )

        print(
            "PASSWORD RESET OTP EMAIL SENT:",
            email
        )

        return True

    except Exception as exc:

        print(
            "RESEND EMAIL ERROR:",
            exc
        )

        raise


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
@app.route(
    "/forgot_password",
    methods=["GET", "POST"]
)
def forgot_password():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        if not username:

            error = (
                "Please enter your admin username."
            )

            return render_template(
                "forgot_password.html",
                error=error
            )

        admin = get_admin_by_username(
            username
        )

        # Do not reveal whether username exists.

        if not admin:

            error = (
                "Unable to process the password reset request."
            )

            try:

                return render_template(
                    "forgot_password.html",
                    error=error
                )

            except TemplateNotFound:

                return (
                    "<h3>Password Reset</h3>"
                    "<p>Unable to process the password reset request.</p>"
                    '<a href="/login">Back to Login</a>',
                    400
                )

        # Generate 6-digit OTP

        otp = str(
            secrets.randbelow(
                1_000_000
            )
        ).zfill(6)

        # Store only OTP hash

        session["reset_admin_id"] = int(
            admin[0]
        )

        session["reset_username"] = str(
            admin[1]
        )

        session["reset_otp_hash"] = hashlib.sha256(
            otp.encode("utf-8")
        ).hexdigest()

        session["reset_otp_expires"] = (
            time.time()
            + OTP_EXPIRY_SECONDS
        )

        session["reset_otp_attempts"] = 0

        session["reset_otp_verified"] = False

        try:

            send_reset_otp(
                otp
            )

        except Exception as exc:

            print(
                "PASSWORD RESET EMAIL ERROR:",
                exc
            )

            for key in (

                "reset_admin_id",
                "reset_username",
                "reset_otp_hash",
                "reset_otp_expires",
                "reset_otp_attempts",
                "reset_otp_verified"
            ):

                session.pop(
                    key,
                    None
                )

            error = (
                "Unable to send OTP. "
                "Check your email configuration."
            )

            try:

                return render_template(
                    "forgot_password.html",
                    error=error
                )

            except TemplateNotFound:

                return (
                    "<h3>Password Reset</h3>"
                    "<p>Unable to send OTP. "
                    "Check your .env email configuration.</p>"
                    '<a href="/login">Back to Login</a>',
                    500
                )

        return redirect(
            "/verify-otp"
        )

    # --------------------------------------------------------
    # GET REQUEST
    # --------------------------------------------------------

    try:

        return render_template(
            "forgot_password.html",
            error=error
        )

    except TemplateNotFound:

        return """
        <!doctype html>
        <html>
        <head>
            <title>Forgot Password</title>
        </head>

        <body style="
            font-family:Arial;
            max-width:420px;
            margin:60px auto;
            padding:20px
        ">

            <h2>Forgot Password</h2>

            <p>
                Enter your admin username to receive a
                6-digit OTP.
            </p>

            {error_html}

            <form method="post">

                <input
                    name="username"
                    required
                    placeholder="Admin username"
                    style="
                        width:100%;
                        padding:10px;
                        margin:10px 0
                    "
                >

                <button
                    type="submit"
                    style="
                        padding:10px 18px
                    "
                >
                    Send OTP
                </button>

            </form>

            <p>
                <a href="/login">
                    Back to Login
                </a>
            </p>

        </body>
        </html>
        """.format(
            error_html=(
                f'<p style="color:red">{error}</p>'
                if error
                else ""
            )
        )


# ============================================================
# VERIFY OTP
# ============================================================

@app.route(
    "/verify-otp",
    methods=["GET", "POST"]
)
def verify_otp():

    if "reset_otp_hash" not in session:

        return redirect(
            "/forgot-password"
        )

    error = None

    try:

        otp_expires = float(
            session.get(
                "reset_otp_expires",
                0
            )
        )

    except (
        TypeError,
        ValueError
    ):

        otp_expires = 0

    if time.time() > otp_expires:

        for key in (

            "reset_otp_hash",
            "reset_otp_expires",
            "reset_otp_attempts",
            "reset_otp_verified"
        ):

            session.pop(
                key,
                None
            )

        return render_template(
            "verify_otp.html",
            error=(
                "OTP has expired. "
                "Please request a new OTP."
            )
        )

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        if (
            not entered_otp.isdigit()
            or len(entered_otp) != 6
        ):

            error = (
                "Enter a valid 6-digit OTP."
            )

        else:

            attempts = int(
                session.get(
                    "reset_otp_attempts",
                    0
                )
            ) + 1

            session["reset_otp_attempts"] = (
                attempts
            )

            entered_hash = hashlib.sha256(
                entered_otp.encode(
                    "utf-8"
                )
            ).hexdigest()

            if attempts > MAX_OTP_ATTEMPTS:

                for key in (

                    "reset_otp_hash",
                    "reset_otp_expires",
                    "reset_otp_attempts",
                    "reset_otp_verified",
                    "reset_verified_expires"
                ):

                    session.pop(
                        key,
                        None
                    )

                return render_template(
                    "verify_otp.html",
                    error=(
                        "Too many OTP attempts. "
                        "Please request a new OTP."
                    )
                )

            if entered_hash != session.get(
                "reset_otp_hash"
            ):

                remaining = max(
                    0,
                    MAX_OTP_ATTEMPTS - attempts
                )

                error = (
                    f"Invalid OTP. "
                    f"Attempts remaining: {remaining}"
                )

            else:

                session["reset_otp_verified"] = True

                session["reset_verified_expires"] = (
                    time.time()
                    + RESET_SESSION_SECONDS
                )

                # OTP can only be used once.

                session.pop(
                    "reset_otp_hash",
                    None
                )

                session.pop(
                    "reset_otp_expires",
                    None
                )

                session.pop(
                    "reset_otp_attempts",
                    None
                )

                return redirect(
                    "/reset-password"
                )

    return render_template(
        "verify_otp.html",
        error=error
    )


# ============================================================
# RESET PASSWORD
# ============================================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    # --------------------------------------------------------
    # OTP VERIFICATION REQUIRED
    # --------------------------------------------------------

    if not session.get(
        "reset_otp_verified"
    ):

        return redirect(
            "/forgot-password"
        )

    # --------------------------------------------------------
    # CHECK RESET SESSION EXPIRY
    # --------------------------------------------------------

    reset_expires = session.get(
        "reset_verified_expires",
        0
    )

    try:

        reset_expires = float(
            reset_expires
        )

    except (
        TypeError,
        ValueError
    ):

        reset_expires = 0

    if time.time() > reset_expires:

        for key in (

            "reset_admin_id",
            "reset_username",
            "reset_otp_verified",
            "reset_verified_expires"
        ):

            session.pop(
                key,
                None
            )

        return redirect(
            "/forgot-password"
        )

    # --------------------------------------------------------
    # GET ADMIN INFORMATION
    # --------------------------------------------------------

    admin_id = session.get(
        "reset_admin_id"
    )

    username = session.get(
        "reset_username"
    )

    if not admin_id or not username:

        for key in (

            "reset_admin_id",
            "reset_username",
            "reset_otp_verified",
            "reset_verified_expires"
        ):

            session.pop(
                key,
                None
            )

        return redirect(
            "/login"
        )

    error = None

    # --------------------------------------------------------
    # POST - NEW PASSWORD
    # --------------------------------------------------------

    if request.method == "POST":

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # PASSWORD VALIDATION
        # ----------------------------------------------------

        if not new_password:

            error = (
                "Please enter a new password."
            )

        elif len(new_password) < 8:

            error = (
                "Password must be at least 8 characters."
            )

        elif new_password != confirm_password:

            error = (
                "Passwords do not match."
            )

        else:

            # ------------------------------------------------
            # UPDATE DATABASE
            # ------------------------------------------------

            try:

                updated = update_admin_password(
                    int(admin_id),
                    new_password
                )

            except Exception as exc:

                print(
                    "PASSWORD UPDATE ERROR:",
                    exc
                )

                updated = False

            if updated:

                # --------------------------------------------
                # CLEAR PASSWORD RESET STATE
                # --------------------------------------------

                for key in (

                    "reset_admin_id",
                    "reset_username",
                    "reset_otp_verified",
                    "reset_verified_expires"
                ):

                    session.pop(
                        key,
                        None
                    )

                # Do not automatically log admin in.

                return redirect(
                    "/login?reset=success"
                )

            error = (
                "Unable to update the password."
            )

    # --------------------------------------------------------
    # IMPORTANT:
    # THIS RETURN HANDLES BOTH GET AND FAILED POST.
    # --------------------------------------------------------

    return render_template(
        "reset_password.html",
        username=username,
        error=error
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        "/login"
    )


# ============================================================
# LOGIN HISTORY
# ============================================================

@app.route("/login_history")
def login_history():

    if not admin_required():

        return redirect(
            "/login"
        )

    logs = get_login_history()

    return render_template(
        "login_history.html",
        logs=logs
    )


@app.route(
    "/clear_login_history",
    methods=["POST", "GET"]
)
def clear_login_history_route():

    if not admin_required():

        return redirect(
            "/login"
        )

    clear_login_history()

    return redirect(
        "/login_history"
    )


# ============================================================
# ADMIN MANAGEMENT
# ============================================================

@app.route(
    "/admins",
    methods=["GET", "POST"]
)
def admins():

    if not admin_required():

        return redirect(
            "/login"
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        confirm_password = request.form.get(
            "confirm_password",
            ""
        ).strip()

        if (
            username == ""
            or password == ""
        ):

            flash(
                "Username and password are required.",
                "danger"
            )

        elif password != confirm_password:

            flash(
                "Password and confirm password do not match.",
                "danger"
            )

        elif len(password) < 4:

            flash(
                "Password must be at least 4 characters.",
                "danger"
            )

        else:

            created = add_admin(
                username,
                password
            )

            if created:

                flash(
                    "New admin added successfully.",
                    "success"
                )

            else:

                flash(
                    "Admin username already exists.",
                    "warning"
                )

        return redirect(
            "/admins"
        )

    admin_list = get_admins()

    return render_template(
        "admins.html",
        admins=admin_list
    )


# ============================================================
# ADMIN PASSWORD RESET FROM ADMIN PANEL
# ============================================================

@app.route(
    "/reset_admin_password/<int:admin_id>",
    methods=["POST"]
)
def reset_admin_password(
    admin_id
):

    if not admin_required():

        return redirect(
            "/login"
        )

    new_password = request.form.get(
        "new_password",
        ""
    ).strip()

    confirm_password = request.form.get(
        "confirm_password",
        ""
    ).strip()

    if new_password == "":

        flash(
            "New password is required.",
            "danger"
        )

    elif new_password != confirm_password:

        flash(
            "New password and confirm password do not match.",
            "danger"
        )

    elif len(new_password) < 4:

        flash(
            "Password must be at least 4 characters.",
            "danger"
        )

    else:

        updated = update_admin_password(
            admin_id,
            new_password
        )

        if updated:

            flash(
                "Admin password reset successfully.",
                "success"
            )

        else:

            flash(
                "Password reset failed.",
                "danger"
            )

    return redirect(
        "/admins"
    )


# ============================================================
# DELETE ADMIN
# ============================================================

@app.route(
    "/delete_admin/<int:admin_id>",
    methods=["POST"]
)
def delete_admin_route(
    admin_id
):

    if not admin_required():

        return redirect(
            "/login"
        )

    admin = get_admin_by_id(
        admin_id
    )

    if not admin:

        flash(
            "Admin not found.",
            "danger"
        )

        return redirect(
            "/admins"
        )

    if count_admins() <= 1:

        flash(
            "You cannot delete the last admin.",
            "danger"
        )

        return redirect(
            "/admins"
        )

    if admin[1] == session.get(
        "admin"
    ):

        flash(
            "You cannot delete the currently logged-in admin.",
            "danger"
        )

        return redirect(
            "/admins"
        )

    deleted = delete_admin(
        admin_id
    )

    if deleted:

        flash(
            "Admin deleted successfully.",
            "success"
        )

    else:

        flash(
            "Admin delete failed.",
            "danger"
        )

    return redirect(
        "/admins"
    )


# ============================================================
# URL DETECTION
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def home():

    result = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        prediction = (
            "URL Scan Error"
        )

        score = 0.0

        risk = "Low"

        try:

            if not url:

                raise Exception(
                    "Please enter a URL"
                )

            if not valid_url(url):

                prediction = (
                    "Invalid URL"
                )

                score = 0.0

                risk = "Low"

            elif whitelist_safe_domain(
                url
            ):

                prediction = (
                    "Legitimate Website"
                )

                score = 5.0

                risk = "Low"

            else:

                if url_model is None:

                    raise Exception(
                        "URL model not loaded"
                    )

                features = extract_features(
                    url
                )

                input_data = make_url_input(
                    features
                )

                probability = url_model.predict_proba(
                    input_data
                )[0][1]

                ml_score = round(
                    float(probability) * 100,
                    2
                )

                rule_score = phishing_rule_score(
                    url
                )

                # Combine ML and deterministic URL rules.
                score = round(
                    max(
                        ml_score,
                        rule_score
                    ),
                    2
                )

                # Strong deterministic URL indicators should produce
                # High Risk even when the ML model is conservative.
                if rule_score >= 75:
                    score = max(
                        score,
                        85.0
                    )

                prediction, risk = classify_url(
                    score
                )

        except Exception as e:

            print(
                "URL ERROR:",
                e
            )

        save_scan(
            "URL",
            url,
            prediction,
            score,
            risk
        )

        result = {

            "url":
                url,

            "prediction":
                prediction,

            "score":
                score,

            "risk":
                risk
        }

    return render_template(
        "index.html",
        result=result
    )


# ============================================================
# EMAIL DETECTION
# ============================================================

@app.route(
    "/email",
    methods=["GET", "POST"]
)
def email():

    result = None

    if request.method == "POST":

        text = request.form.get(
            "email_text",
            ""
        ).strip()

        prediction = (
            "Email Scan Error"
        )

        score = 0.0

        risk = "Low"

        indicators = {

            "suspicious_links": 0,
            "urgent_words": 0,
            "credential_words": 0,
            "fake_sender": 0
        }

        keywords = []

        links = []

        reasons = []

        try:

            if not text:

                raise Exception(
                    "Please enter email text"
                )

            clean_text = clean_sender_input(
                text
            )

            if is_sender_only_input(
                clean_text
            ):

                text_result = sender_only_decision(
                    clean_text
                )

                if text_result is None:

                    text_result = predict_text_phishing(
                        text,
                        category="email"
                    )

            else:

                text_result = predict_text_phishing(
                    text,
                    category="email"
                )

            prediction = text_result[
                "prediction"
            ]

            score = text_result[
                "score"
            ]

            risk = text_result[
                "risk"
            ]

            indicators = text_result[
                "indicators"
            ]

            keywords = text_result.get(
                "keywords",
                extract_suspicious_keywords(
                    text
                )
            )

            links = text_result.get(
                "links",
                extract_links(
                    text
                )
            )

            reasons = text_result.get(
                "reasons",
                []
            )

            forced_indicators = calculate_email_indicators(
                text,
                email_features_to_dict(
                    text
                )
            )

            if prediction in [
                "Phishing Email",
                "Suspicious Email"
            ]:

                indicators = {

                    "suspicious_links":
                        max(
                            int(
                                indicators.get(
                                    "suspicious_links",
                                    0
                                )
                            ),
                            int(
                                forced_indicators.get(
                                    "suspicious_links",
                                    0
                                )
                            )
                        ),

                    "urgent_words":
                        max(
                            int(
                                indicators.get(
                                    "urgent_words",
                                    0
                                )
                            ),
                            int(
                                forced_indicators.get(
                                    "urgent_words",
                                    0
                                )
                            )
                        ),

                    "credential_words":
                        max(
                            int(
                                indicators.get(
                                    "credential_words",
                                    0
                                )
                            ),
                            int(
                                forced_indicators.get(
                                    "credential_words",
                                    0
                                )
                            )
                        ),

                    "fake_sender":
                        max(
                            int(
                                indicators.get(
                                    "fake_sender",
                                    0
                                )
                            ),
                            int(
                                forced_indicators.get(
                                    "fake_sender",
                                    0
                                )
                            )
                        )
                }

        except Exception:

            import traceback

            print(
                "\nEMAIL ERROR:"
            )

            traceback.print_exc()

            reasons = [
                "Email scan failed"
            ]

        save_scan(
            "EMAIL",
            text[:200],
            prediction,
            score,
            risk
        )

        result = {

            "email":
                text,

            "prediction":
                prediction,

            "score":
                score,

            "risk":
                risk,

            "indicators":
                indicators,

            "keywords":
                keywords,

            "links":
                links,

            "reasons":
                reasons
        }

    return render_template(
        "email.html",
        result=result
    )


# ============================================================
# CONTENT CHECKING
# ============================================================

@app.route(
    "/content",
    methods=["GET", "POST"]
)
def content_check():

    result = None

    if request.method == "POST":

        text = request.form.get(
            "content_text",
            ""
        ).strip()

        try:

            if not text:

                raise Exception(
                    "Please enter content"
                )

            result = predict_text_phishing(
                text,
                category="content"
            )

            result = normalize_text_result_category(
                result,
                "content"
            )

            save_scan(
                "CONTENT",
                text[:200],
                result["prediction"],
                result["score"],
                result["risk"]
            )

        except Exception as e:

            print(
                "CONTENT CHECK ERROR:",
                e
            )

            result = {

                "prediction":
                    "Content Scan Error",

                "score":
                    0.0,

                "risk":
                    "Low",

                "keywords":
                    [],

                "links":
                    [],

                "reasons":
                    ["Content scan failed"],

                "indicators": {

                    "suspicious_links": 0,
                    "urgent_words": 0,
                    "credential_words": 0,
                    "fake_sender": 0
                }
            }

            save_scan(
                "CONTENT",
                text[:200],
                result["prediction"],
                result["score"],
                result["risk"]
            )

    return render_template(
        "content.html",
        result=result
    )


# ============================================================
# FILE VERIFICATION
# ============================================================

@app.route(
    "/file",
    methods=["GET", "POST"]
)
def file_verification():

    result = None

    if request.method == "POST":

        uploaded_file = request.files.get(
            "file"
        )

        try:

            if (
                not uploaded_file
                or not uploaded_file.filename
            ):

                raise Exception(
                    "Please upload a file"
                )

            original_filename = (
                uploaded_file.filename
            )

            filename = make_safe_upload_name(
                original_filename
            )

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )

            uploaded_file.save(
                file_path
            )

            result = verify_uploaded_file(
                file_path,
                original_filename
            )

            save_scan(
                "FILE",
                original_filename,
                result["prediction"],
                result["score"],
                result["risk"]
            )

        except Exception as e:

            print(
                "FILE VERIFICATION ERROR:",
                e
            )

            result = {

                "filename":
                    uploaded_file.filename
                    if uploaded_file
                    else "No file",

                "extension":
                    "",

                "size_mb":
                    0,

                "hash":
                    "",

                "prediction":
                    "File Scan Error",

                "score":
                    0.0,

                "risk":
                    "Low",

                "reasons":
                    ["File verification failed"],

                "content_result":
                    None,

                "extracted_text":
                    ""
            }

            save_scan(
                "FILE",
                result["filename"],
                result["prediction"],
                result["score"],
                result["risk"]
            )

    return render_template(
        "file.html",
        result=result
    )


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
def history():

    if not admin_required():

        return redirect(
            "/login"
        )

    scans = get_history()

    return render_template(
        "history.html",
        scans=scans
    )


@app.route(
    "/delete_scan/<int:id>"
)
def delete_scan_route(id):

    if not admin_required():

        return redirect(
            "/login"
        )

    delete_scan(
        id
    )

    return redirect(
        "/history"
    )


@app.route("/clear_history")
def clear_history_route():

    if not admin_required():

        return redirect(
            "/login"
        )

    clear_history()

    return redirect(
        "/history"
    )


# ============================================================
# EXPORT HISTORY CSV
# ============================================================

@app.route(
    "/export_history_csv"
)
def export_history_csv():

    if not admin_required():

        return redirect(
            "/login"
        )

    scans = get_history()

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow([

        "ID",
        "Type",
        "Input",
        "Prediction",
        "Score",
        "Risk",
        "Date"
    ])

    for scan in scans:

        writer.writerow([

            scan[0],
            scan[1],
            scan[2],
            scan[3],
            scan[4],
            scan[5],
            scan[6]
        ])

    response = make_response(
        "\ufeff"
        + output.getvalue()
    )

    filename = (
        "scan_history_"
        + datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        + ".csv"
    )

    response.headers[
        "Content-Disposition"
    ] = (
        f"attachment; filename={filename}"
    )

    response.headers[
        "Content-Type"
    ] = (
        "text/csv; charset=utf-8"
    )

    return response


# ============================================================
# EXPORT HISTORY PDF
# ============================================================

@app.route(
    "/export_history_pdf"
)
def export_history_pdf():

    if not admin_required():

        return redirect(
            "/login"
        )

    scans = get_history()

    try:

        from reportlab.lib.pagesizes import (
            landscape,
            A4
        )

        from reportlab.platypus import (
            SimpleDocTemplate,
            Table,
            TableStyle,
            Paragraph,
            Spacer
        )

        from reportlab.lib import colors

        from reportlab.lib.styles import (
            getSampleStyleSheet
        )

        buffer = io.BytesIO()

        doc = SimpleDocTemplate(

            buffer,

            pagesize=landscape(A4),

            rightMargin=20,

            leftMargin=20,

            topMargin=20,

            bottomMargin=20
        )

        elements = []

        styles = getSampleStyleSheet()

        title = Paragraph(

            "AI Phishing Detection Site - Scan History Report",

            styles["Title"]
        )

        elements.append(
            title
        )

        elements.append(
            Spacer(
                1,
                15
            )
        )

        data = [[

            "ID",
            "Type",
            "Input",
            "Prediction",
            "Score",
            "Risk",
            "Date"
        ]]

        for scan in scans:

            input_text = str(
                scan[2]
            )

            if len(input_text) > 45:

                input_text = (
                    input_text[:45]
                    + "..."
                )

            data.append([

                scan[0],
                scan[1],
                input_text,
                scan[3],
                str(
                    scan[4]
                ) + "%",
                scan[5],
                scan[6]
            ])

        if len(data) == 1:

            data.append([

                "-",
                "-",
                "No scan history available",
                "-",
                "-",
                "-",
                "-"
            ])

        table = Table(

            data,

            colWidths=[
                35,
                60,
                230,
                120,
                60,
                70,
                130
            ]
        )

        table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#111827"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER"
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, 0),
                    10
                ),

                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.HexColor(
                        "#f8fafc"
                    )
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                )
            ])
        )

        elements.append(
            table
        )

        doc.build(
            elements
        )

        pdf = buffer.getvalue()

        buffer.close()

        response = make_response(
            pdf
        )

        filename = (
            "scan_history_"
            + datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
            + ".pdf"
        )

        response.headers[
            "Content-Disposition"
        ] = (
            f"attachment; filename={filename}"
        )

        response.headers[
            "Content-Type"
        ] = "application/pdf"

        return response

    except Exception as e:

        print(
            "PDF EXPORT ERROR:",
            e
        )

        return (
            "PDF export failed. "
            "Install reportlab using: "
            "pip install reportlab"
        )


# ============================================================
# DEDUCTION REPORT / DASHBOARD
# ============================================================

@app.route(
    "/dashboard"
)
@app.route(
    "/deduction-report"
)
def dashboard():

    stats = get_dashboard_stats()

    return render_template(
        "dashboard.html",
        **stats
    )


# ============================================================
# ANALYTICS API
# ============================================================

@app.route(
    "/analytics"
)
def analytics():

    stats = get_dashboard_stats()

    return jsonify({

        "status":
            "running",

        "stats":
            stats
    })


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    debug_mode = (
        os.getenv(
            "FLASK_DEBUG",
            "0"
        ) == "1"
    )

    app.run(
        debug=debug_mode
    )