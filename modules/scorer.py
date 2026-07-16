# ===================================
#  Trust Me Bro — Risk Scorer
#  Evaluates collected data and
#  produces a weighted risk score
# ===================================

from config import (
    DOMAIN_AGE_DAYS_THRESHOLD,
    EXTERNAL_RESOURCE_THRESHOLD,
    KNOWN_BRANDS,
    REDIRECT_THRESHOLD,
    SCORING_WEIGHTS,
    SUBDOMAIN_DOT_THRESHOLD,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_LENGTH_THRESHOLD,
)

# Leetspeak / homoglyph normalization map
_LEET_MAP = str.maketrans("013457@!$", "oieastais")


def _normalize_for_brand(text):
    """Normalize a domain string for brand comparison.

    - Lowercases
    - Translates common leetspeak characters (0→o, 1→i/l, 3→e, etc.)
    - Removes hyphens and digits
    """
    text = text.lower().translate(_LEET_MAP)
    text = text.replace("-", "").replace("_", "")
    # Remove remaining digits (e.g. "netf1ix" → "netflix" after leet translate,
    # but if any digit survives, strip it)
    text = "".join(ch for ch in text if not ch.isdigit())
    return text


def _brand_matches_domain(domain, registered_domain):
    """Check if a domain impersonates a known brand.

    Uses multiple strategies:
      1. Exact substring (original logic — fast path)
      2. Normalized substring (catches leetspeak like netf1ix → netflix)
      3. Edit-distance ratio (catches typosquatting like gooogle, amazn)
    """
    for brand, legit_domains in KNOWN_BRANDS.items():
        if registered_domain in legit_domains:
            continue  # This is the real brand domain

        # Strategy 1: exact substring
        if brand in domain:
            return True

        # Strategy 2: normalized substring
        norm_domain = _normalize_for_brand(domain)
        norm_brand = _normalize_for_brand(brand)
        if len(norm_brand) >= 4 and norm_brand in norm_domain:
            return True

        # Strategy 3: edit distance ratio on normalized strings
        # Only check if lengths are similar (within 40% of each other)
        if len(norm_brand) > 0:
            ratio = abs(len(norm_domain) - len(norm_brand)) / len(norm_brand)
            if ratio <= 0.4:
                distance = _edit_distance(norm_domain, norm_brand)
                max_len = max(len(norm_domain), len(norm_brand))
                similarity = 1 - (distance / max_len)
                if similarity >= 0.7:
                    return True

    return False


def _edit_distance(s1, s2):
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def score(collected_data):
    """
    Evaluate collected URL data and return (risk_score, triggered_indicators).

    Each triggered indicator is a dict:
        {"key": str, "points": int, "label": str}
    """
    triggered = []

    url_features = collected_data.get("url_features", {})
    tld_info = collected_data.get("tld_info", {})
    whois_data = collected_data.get("whois_data", {})
    ssl_data = collected_data.get("ssl_data", {})
    http_data = collected_data.get("http_data", {})
    page_data = collected_data.get("page_data", {})
    url = collected_data.get("url", "")

    # 1. IP-based URL
    if url_features.get("is_ip_address"):
        triggered.append(_indicator("ip_based_url"))

    # 2. Suspicious TLD
    suffix = (tld_info.get("suffix") or "").lower()
    if suffix in SUSPICIOUS_TLDS:
        triggered.append(_indicator("suspicious_tld"))

    # 3. Very long URL
    if url_features.get("length", 0) > URL_LENGTH_THRESHOLD:
        triggered.append(_indicator("long_url"))

    # 4. '@' symbol
    if url_features.get("has_at_symbol"):
        triggered.append(_indicator("at_symbol"))

    # 5. Excessive subdomains
    if url_features.get("dot_count", 0) > SUBDOMAIN_DOT_THRESHOLD:
        triggered.append(_indicator("excessive_subdomains"))

    # 6. Recently registered domain
    if whois_data.get("success"):
        age = whois_data.get("domain_age_days")
        if age is not None and age < DOMAIN_AGE_DAYS_THRESHOLD:
            triggered.append(_indicator("young_domain"))
    else:
        # 7. WHOIS lookup failed
        triggered.append(_indicator("whois_failed"))

    # 8. Invalid / missing SSL
    if not ssl_data.get("valid"):
        triggered.append(_indicator("invalid_ssl"))

    # 9. Multiple redirects
    redirect_count = http_data.get("redirect_count", 0)
    if redirect_count > REDIRECT_THRESHOLD:
        triggered.append(_indicator("many_redirects"))

    # 10. Suspicious keywords in URL path
    url_lower = url.lower()
    if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS):
        triggered.append(_indicator("suspicious_keywords"))

    # 11. Brand impersonation (fuzzy matching)
    domain = (tld_info.get("domain") or "").lower()
    registered = (tld_info.get("registered_domain") or "").lower()
    if _brand_matches_domain(domain, registered):
        triggered.append(_indicator("brand_impersonation"))

    # 12. Password fields on page
    if page_data.get("success") and page_data.get("password_field_count", 0) > 0:
        triggered.append(_indicator("password_fields"))

    # 13. Many external resources
    if page_data.get("success") and page_data.get("external_domain_count", 0) > EXTERNAL_RESOURCE_THRESHOLD:
        triggered.append(_indicator("many_external_res"))

    # 14. Suspicious page title (keywords OR error/parked patterns)
    title = (page_data.get("title") or "").lower()
    if page_data.get("success") and title:
        suspicious_title_patterns = [
            "402", "403", "404", "parked", "domain for sale",
            "renew", "expired", "subscription",
        ]
        title_match = (
            any(kw in title for kw in SUSPICIOUS_KEYWORDS)
            or any(pat in title for pat in suspicious_title_patterns)
        )
        if title_match:
            triggered.append(_indicator("suspicious_title"))

    # Calculate total score (capped at 100)
    risk_score = min(sum(ind["points"] for ind in triggered), 100)

    return risk_score, triggered


def _indicator(key):
    """Build an indicator dict from its config key."""
    points, label = SCORING_WEIGHTS[key]
    return {"key": key, "points": points, "label": label}
