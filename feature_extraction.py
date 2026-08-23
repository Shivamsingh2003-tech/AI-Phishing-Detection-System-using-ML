from urllib.parse import urlparse
import re
import math


def entropy(text):
    if not text:
        return 0

    probs = [
        text.count(c) / len(text)
        for c in set(text)
    ]

    return round(
        -sum(p * math.log2(p) for p in probs),
        3
    )


def extract_features(url):
    if not url:
        url = ""

    url = url.strip()

    if url and not url.startswith(("http://", "https://")):
        parsed = urlparse("http://" + url)
    else:
        parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    url_lower = url.lower()

    url_length = len(url)
    safe_length = max(url_length, 1)

    domain_length = len(domain)
    path_length = len(path)
    query_length = len(query)

    having_ip = int(
        bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain.split(":")[0]
            )
        )
    )

    dots = domain.count(".")
    subdomains = max(0, dots - 1)
    hyphen = domain.count("-")

    https = int(url_lower.startswith("https://"))

    shortening_domains = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "rb.gy",
        "ow.ly",
        "is.gd"
    ]

    shortening = int(
        any(domain == x or domain.endswith("." + x) for x in shortening_domains)
    )

    suspicious_tlds = [
        ".xyz",
        ".club",
        ".top",
        ".site",
        ".online",
        ".tk",
        ".cf",
        ".ml",
        ".ga",
        ".gq"
    ]

    suspicious_tld = int(
        any(domain.endswith(tld) for tld in suspicious_tlds)
    )

    at_symbol = url.count("@")
    slash = url.count("/")
    question = url.count("?")
    equal = url.count("=")
    percent = url.count("%")
    underscore = url.count("_")
    dash = url.count("-")
    amp = url.count("&")

    digits = sum(c.isdigit() for c in url)

    special = len(
        re.findall(
            r"[!@#$%^&*()_+=<>?]",
            url
        )
    )

    double_slash = int("//" in path)

    keywords = [
        "login",
        "signin",
        "verify",
        "secure",
        "security",
        "bank",
        "update",
        "paypal",
        "account",
        "confirm",
        "free",
        "offer",
        "gift",
        "alert",
        "support",
        "password",
        "suspended"
    ]

    keyword_count = sum(
        1 for k in keywords
        if re.search(rf"(^|[^a-zA-Z0-9]){re.escape(k)}([^a-zA-Z0-9]|$)", url_lower)
    )

    # Brand impersonation check
    trusted_brands = [
        "google",
        "github",
        "amazon",
        "paypal",
        "microsoft",
        "linkedin",
        "facebook",
        "apple",
        "netflix"
    ]

    official_domains = [
        "google.com",
        "www.google.com",
        "github.com",
        "www.github.com",
        "amazon.com",
        "www.amazon.com",
        "paypal.com",
        "www.paypal.com",
        "microsoft.com",
        "www.microsoft.com",
        "linkedin.com",
        "www.linkedin.com",
        "facebook.com",
        "www.facebook.com",
        "apple.com",
        "www.apple.com",
        "netflix.com",
        "www.netflix.com"
    ]

    brand_impersonation = 0

    if domain not in official_domains:
        for brand in trusted_brands:
            if brand in domain:
                brand_impersonation = 1
                break

    # Add brand impersonation effect into keyword count
    if brand_impersonation:
        keyword_count += 2

    entropy_score = entropy(url)

    ratio_digits = round(
        digits / safe_length,
        4
    )

    ratio_special = round(
        special / safe_length,
        4
    )

    return [
        having_ip,
        url_length,
        domain_length,
        path_length,
        query_length,
        dots,
        subdomains,
        hyphen,
        https,
        shortening,
        suspicious_tld,
        at_symbol,
        slash,
        question,
        equal,
        percent,
        underscore,
        dash,
        amp,
        digits,
        special,
        double_slash,
        keyword_count,
        entropy_score,
        ratio_digits,
        ratio_special
    ]