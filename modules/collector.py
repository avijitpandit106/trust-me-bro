# ===================================
#  Trust Me Bro — Data Collector
#  Gathers raw information about a URL
# ===================================

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT


def collect(url):
    """
    Collect raw data about a URL for analysis.

    Returns a dict with keys:
        url, parsed, tld_info, url_features,
        whois_data, ssl_data, http_data, page_data
    """
    result = {
        "url": url,
        "parsed": _parse_url(url),
        "tld_info": _extract_tld(url),
        "url_features": _url_features(url),
        "whois_data": _whois_lookup(url),
        "ssl_data": _check_ssl(url),
        "http_data": _http_probe(url),
        "page_data": _fetch_page(url),
    }
    return result


# ------------------------------------------------------------------
#  URL Parsing
# ------------------------------------------------------------------

def _parse_url(url):
    """Break URL into components using urllib."""
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def _extract_tld(url):
    """Use tldextract to get domain, subdomain, and suffix."""
    ext = tldextract.extract(url)
    return {
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": ext.registered_domain,
    }


# ------------------------------------------------------------------
#  URL Feature Extraction
# ------------------------------------------------------------------

def _url_features(url):
    """Compute surface-level features of the URL string."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Check if hostname is a raw IP address
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    return {
        "length": len(url),
        "has_at_symbol": "@" in url,
        "is_ip_address": is_ip,
        "dot_count": hostname.count("."),
        "special_char_count": sum(1 for c in url if c in "-_~!$&'()*+,;="),
        "path_length": len(parsed.path),
    }


# ------------------------------------------------------------------
#  WHOIS Lookup
# ------------------------------------------------------------------

def _whois_lookup(url):
    """Attempt WHOIS lookup for domain age and registrar."""
    try:
        import whois  # python-whois

        ext = tldextract.extract(url)
        domain = ext.registered_domain
        if not domain:
            return {"success": False, "error": "No registered domain found"}

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        domain_age_days = None
        if creation_date:
            now = datetime.now()
            if creation_date.tzinfo is not None:
                now = datetime.now(timezone.utc)
            delta = now - creation_date
            domain_age_days = delta.days

        return {
            "success": True,
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "domain_age_days": domain_age_days,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ------------------------------------------------------------------
#  SSL Certificate Check
# ------------------------------------------------------------------

def _check_ssl(url):
    """Check if the host has a valid SSL certificate."""
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {"success": False, "valid": False, "error": "No hostname"}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                not_after = cert.get("notAfter", "")
                return {
                    "success": True,
                    "valid": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "expires": not_after,
                }
    except Exception as e:
        return {"success": False, "valid": False, "error": str(e)}


# ------------------------------------------------------------------
#  HTTP Probe
# ------------------------------------------------------------------

def _http_probe(url):
    """Make an HTTP request and observe redirects and status."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "TrustMeBro/1.0 PhishingScanner"},
            verify=False,  # we check SSL separately
        )
        return {
            "success": True,
            "status_code": resp.status_code,
            "redirect_count": len(resp.history),
            "final_url": resp.url,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ------------------------------------------------------------------
#  Page Content Fetch
# ------------------------------------------------------------------

def _fetch_page(url):
    """Download and parse the HTML page for content indicators."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "TrustMeBro/1.0 PhishingScanner"},
            verify=False,
        )
        soup = BeautifulSoup(resp.text, "html.parser")

        # Page title
        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else ""

        # Password fields
        password_inputs = soup.find_all("input", attrs={"type": "password"})

        # Count forms
        forms = soup.find_all("form")

        # External resources (scripts and links with absolute URLs)
        parsed_url = urlparse(url)
        own_domain = parsed_url.hostname or ""

        external_domains = set()
        for tag in soup.find_all(["script", "link", "img"]):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith(("http://", "https://")):
                ext_host = urlparse(src).hostname
                if ext_host and ext_host != own_domain:
                    external_domains.add(ext_host)

        return {
            "success": True,
            "title": title,
            "password_field_count": len(password_inputs),
            "form_count": len(forms),
            "external_domain_count": len(external_domains),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
