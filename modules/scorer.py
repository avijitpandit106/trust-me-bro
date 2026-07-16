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

    # 11. Brand impersonation
    domain = (tld_info.get("domain") or "").lower()
    registered = (tld_info.get("registered_domain") or "").lower()
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in domain and registered not in legit_domains:
            triggered.append(_indicator("brand_impersonation"))
            break

    # 12. Password fields on page
    if page_data.get("success") and page_data.get("password_field_count", 0) > 0:
        triggered.append(_indicator("password_fields"))

    # 13. Many external resources
    if page_data.get("success") and page_data.get("external_domain_count", 0) > EXTERNAL_RESOURCE_THRESHOLD:
        triggered.append(_indicator("many_external_res"))

    # 14. Suspicious page title
    title = (page_data.get("title") or "").lower()
    if page_data.get("success") and any(kw in title for kw in SUSPICIOUS_KEYWORDS):
        triggered.append(_indicator("suspicious_title"))

    # Calculate total score (capped at 100)
    risk_score = min(sum(ind["points"] for ind in triggered), 100)

    return risk_score, triggered


def _indicator(key):
    """Build an indicator dict from its config key."""
    points, label = SCORING_WEIGHTS[key]
    return {"key": key, "points": points, "label": label}
