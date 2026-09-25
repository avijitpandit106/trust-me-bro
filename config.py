	# ===================================
#  Trust Me Bro — Configuration
#  Central constants for the backend
# ===================================

import os

# ------------------------------------
#  General
# ------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DATABASE_PATH = os.path.join(BASE_DIR, "database", "phishing_scans.db")

# HTTP request timeout (seconds)
REQUEST_TIMEOUT = 5

# ------------------------------------
#  Classification Thresholds
# ------------------------------------
# risk_score ranges → classification label + CSS badge class

CLASSIFICATIONS = [
    # (max_score_inclusive, label, badge_css_class)
    (30, "Safe", "safe"),
    (60, "Suspicious", "suspicious"),
    (85, "High Risk", "high-risk"),
    (100, "Critical", "malicious"),
]

# ------------------------------------
#  Scoring Weights
# ------------------------------------
# Each key maps to (points, human-readable indicator name)

SCORING_WEIGHTS = {
    "ip_based_url":         (20, "IP-based URL detected"),
    "suspicious_tld":       (10, "Suspicious top-level domain"),
    "long_url":             (8,  "Unusually long URL"),
    "at_symbol":            (12, "'@' symbol found in URL"),
    "excessive_subdomains": (10, "Excessive subdomains"),
    "young_domain":         (15, "Recently registered domain"),
    "whois_failed":         (8,  "WHOIS lookup failed"),
    "invalid_ssl":          (15, "Invalid or missing SSL certificate"),
    "many_redirects":       (8,  "Multiple HTTP redirects detected"),
    "suspicious_keywords":  (10, "Suspicious keywords in URL"),
    "brand_impersonation":  (15, "Possible brand impersonation"),
    "password_fields":      (10, "Password input fields detected"),
    "many_external_res":    (5,  "High number of external resources"),
    "suspicious_title":     (5,  "Suspicious page title"),
}

# ------------------------------------
#  Thresholds for Indicator Triggers
# ------------------------------------

URL_LENGTH_THRESHOLD = 75        # characters
SUBDOMAIN_DOT_THRESHOLD = 3     # dot-separated levels
DOMAIN_AGE_DAYS_THRESHOLD = 180  # days
REDIRECT_THRESHOLD = 2           # number of redirects
EXTERNAL_RESOURCE_THRESHOLD = 10 # external domains loaded

# ------------------------------------
#  Suspicious TLDs
# ------------------------------------

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "gq", "tk", "ml", "cf", "ga",
    "cam", "icu", "club", "work", "info", "online", "site", "live",
    "store", "tech", "fun", "wang", "win", "bid", "stream",
    "download", "racing", "loan", "date", "trade", "review",
    "accountant", "science", "party", "cricket",
}

# ------------------------------------
#  Suspicious Keywords
# ------------------------------------

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "banking", "password", "credential", "confirm",
    "wallet", "paypal", "suspend", "alert", "notification",
    "unusual", "expire", "locked", "urgent", "immediately",
    "click-here", "free", "winner", "prize", "reward",
}

# ------------------------------------
#  Known Brands (for impersonation)
# ------------------------------------
# Maps brand keyword → set of legitimate registered domains

KNOWN_BRANDS = {
    "paypal":    {"paypal.com"},
    "google":    {"google.com", "google.co.in", "google.co.uk"},
    "apple":     {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "amazon":    {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook":  {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix":   {"netflix.com"},
    "twitter":   {"twitter.com", "x.com"},
    "linkedin":  {"linkedin.com"},
    "whatsapp":  {"whatsapp.com"},
    "telegram":  {"telegram.org"},
    "dropbox":   {"dropbox.com"},
    "github":    {"github.com"},
    "chase":     {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citi":      {"citi.com", "citibank.com"},
}

# ------------------------------------
#  Recommendations by Classification
# ------------------------------------

RECOMMENDATIONS = {
    "Safe": [
        "This website appears to be legitimate.",
        "Standard internet safety practices still apply.",
    ],
    "Suspicious": [
        "Exercise caution when interacting with this website.",
        "Avoid entering sensitive information unless you are certain of its legitimacy.",
        "Verify the website through an independent source.",
    ],
    "High Risk": [
        "Do not enter any personal or financial information.",
        "Do not download files from this website.",
        "Report this URL to your IT administrator.",
        "Consider blocking this domain.",
    ],
    "Critical": [
        "Do not visit this website under any circumstances.",
        "Do not submit any credentials or payment details.",
        "Report this URL to your IT administrator immediately.",
        "Block this domain at the network level.",
        "If you have already interacted with this site, change your passwords immediately.",
    ],
}
