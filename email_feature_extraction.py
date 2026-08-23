import re
from urllib.parse import urlparse


# ==========================
# FAKE SENDER DETECTION
# ==========================

def detect_fake_sender(email_text):
    text = email_text.lower()

    sender_match = re.search(
        r'from:\s*[\w\.-]+@([\w\.-]+)',
        text
    )

    if not sender_match:
        sender_match = re.search(
            r'[\w\.-]+@([\w\.-]+)',
            text
        )

    if not sender_match:
        return 0

    sender_domain = sender_match.group(1).lower()

    official_domains = {
        "amazon": ["amazon.com", "amazon.in"],
        "microsoft": ["microsoft.com", "outlook.com"],
        "google": ["google.com", "gmail.com"],
        "github": ["github.com"],
        "linkedin": ["linkedin.com"],
        "paypal": ["paypal.com"],
        "facebook": ["facebook.com"],
        "apple": ["apple.com"],
        "netflix": ["netflix.com"],
        "bank": ["bank.com"]
    }

    for brand, domains in official_domains.items():
        if brand in text:
            if not any(sender_domain.endswith(domain) for domain in domains):
                return 1

    return 0


def extract_email_features(email_text):
    text = email_text.lower()

    urls = re.findall(r'https?://[^\s]+', text)

    links = len(urls)

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "rb.gy",
        "ow.ly",
        "is.gd"
    ]

    short_links = 0
    ip_links = 0
    suspicious_url_count = 0

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if any(short in domain for short in shortener_domains):
            short_links += 1

        if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            ip_links += 1

        if url.startswith("http://"):
            suspicious_url_count += 1

        if "-" in domain:
            suspicious_url_count += 1

        if domain.endswith((".tk", ".xyz", ".top", ".site", ".online", ".club", ".cf", ".ml", ".ga")):
            suspicious_url_count += 1

    urgent_keywords = [
        "urgent",
        "verify",
        "immediately",
        "warning",
        "act now",
        "suspended",
        "update",
        "security",
        "alert",
        "expire",
        "limited time",
        "click now",
        "blocked",
        "locked",
        "unusual activity"
    ]

    urgent_words = sum(1 for word in urgent_keywords if word in text)

    credential_keywords = [
        "password",
        "otp",
        "pin",
        "cvv",
        "credit card",
        "login",
        "signin",
        "account",
        "bank",
        "verification",
        "username",
        "credentials",
        "confirm identity"
    ]

    credential_words = sum(1 for word in credential_keywords if word in text)

    brand_keywords = [
        "paypal",
        "google",
        "amazon",
        "facebook",
        "microsoft",
        "apple",
        "netflix",
        "bank",
        "linkedin",
        "github"
    ]

    sender_score = sum(1 for word in brand_keywords if word in text)

    fake_sender = detect_fake_sender(email_text)

    capital_letters = sum(1 for c in email_text if c.isupper())

    exclamations = email_text.count("!")

    email_length = len(email_text)

    digits = sum(1 for c in email_text if c.isdigit())

    special_chars = len(
        re.findall(
            r"[!@#$%^&*()_+=<>?/\\|{}\[\]:;]",
            email_text
        )
    )

    money_keywords = [
        "payment",
        "invoice",
        "refund",
        "transaction",
        "money",
        "reward",
        "prize",
        "cashback",
        "offer"
    ]

    money_score = sum(1 for word in money_keywords if word in text)

    attachments = len(
        re.findall(
            r"\.(pdf|zip|exe|docx|xlsx|rar|apk)",
            text
        )
    )

    return [
        links,
        short_links,
        ip_links,
        urgent_words,
        credential_words,
        sender_score,
        fake_sender,
        capital_letters,
        exclamations,
        email_length,
        digits,
        special_chars,
        money_score,
        attachments
    ]