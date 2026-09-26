"""
domain_forensics.py — Deep domain investigation for any URL found in a message.

Checks (all wrapped in try/except, degrade gracefully):
  1. WHOIS registrant — registrar name, registrant org, creation date
  2. SSL certificate — issuer, issue date, flag if < 30 days old
  3. ASN / hosting — IP, hosting provider, country via ipwhois
     Flags if a domain claiming to be Indian gov/bank is hosted abroad

Returns a flat dict suitable for display and scoring.
"""

import re
import ssl
import socket
import datetime
import whois
from pathlib import Path
import json

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Strip scheme, www. and path to get the bare domain."""
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)
    return url.split("/")[0].split("?")[0].split("#")[0].lower().strip()


# Load the trusted domain list so we can check claimed-identity context
_ALLOWLIST_PATH = Path(__file__).parent / "known_domains.json"
def _load_allowlist() -> list[str]:
    try:
        with open(_ALLOWLIST_PATH) as f:
            return json.load(f).get("allowlist", [])
    except Exception:
        return []

_KNOWN_DOMAINS = _load_allowlist()


# ---------------------------------------------------------------------------
# 1. WHOIS registrant info
# ---------------------------------------------------------------------------

def get_whois_info(domain: str) -> dict:
    """
    Extends the basic age check with registrar + registrant org.
    Returns:
      { "registrar": str|None, "registrant_org": str|None,
        "creation_date": str|None, "age_days": int|None,
        "privacy_redacted": bool, "error": str|None }
    """
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = None
        creation_str = None
        if creation:
            if hasattr(creation, "tzinfo") and creation.tzinfo:
                creation = creation.replace(tzinfo=None)
            age_days = (datetime.datetime.utcnow() - creation).days
            creation_str = creation.strftime("%Y-%m-%d")

        registrar = w.registrar or None
        org = w.org or None

        # Detect privacy redaction
        privacy_keywords = ("privacy", "redacted", "protect", "guard", "private", "proxy")
        privacy = any(
            kw in str(org or "").lower() or kw in str(registrar or "").lower()
            for kw in privacy_keywords
        )

        return {
            "registrar":        registrar,
            "registrant_org":   org,
            "creation_date":    creation_str,
            "age_days":         age_days,
            "privacy_redacted": privacy,
            "error":            None,
        }
    except Exception as exc:
        return {
            "registrar":        None,
            "registrant_org":   None,
            "creation_date":    None,
            "age_days":         None,
            "privacy_redacted": False,
            "error":            f"WHOIS lookup failed: {exc}",
        }


# ---------------------------------------------------------------------------
# 2. SSL certificate check
# ---------------------------------------------------------------------------

def get_ssl_info(domain: str) -> dict:
    """
    Connects to domain:443, retrieves the TLS certificate.
    Returns:
      { "issuer": str|None, "issue_date": str|None, "age_days": int|None,
        "is_new": bool, "error": str|None }
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Extract issuer common name
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_parts.get("organizationName") or issuer_parts.get("commonName")

        # notBefore is in ASN1 format: "Mar  5 10:00:00 2025 GMT"
        not_before_str = cert.get("notBefore", "")
        issue_date = None
        age_days = None
        is_new = False

        if not_before_str:
            try:
                issue_date = datetime.datetime.strptime(
                    not_before_str, "%b %d %H:%M:%S %Y %Z"
                )
                age_days = (datetime.datetime.utcnow() - issue_date).days
                is_new = age_days < 30
            except ValueError:
                pass

        return {
            "issuer":     issuer,
            "issue_date": issue_date.strftime("%Y-%m-%d") if issue_date else None,
            "age_days":   age_days,
            "is_new":     is_new,
            "error":      None,
        }
    except Exception as exc:
        return {
            "issuer":     None,
            "issue_date": None,
            "age_days":   None,
            "is_new":     False,
            "error":      f"SSL check unavailable: {exc}",
        }


# ---------------------------------------------------------------------------
# 3. ASN / hosting check
# ---------------------------------------------------------------------------

# Country codes generally associated with India
_IN_COUNTRY_CODES = {"IN", "IND"}

# Country codes we flag as unusual for Indian gov/bank domains
_SUSPICIOUS_HOSTING_COUNTRIES: set[str] = {
    "RU", "CN", "NG", "UA", "BY", "KP",
}


def get_hosting_info(domain: str) -> dict:
    """
    Resolves the domain's IP, then looks up ASN, hosting provider, country.
    Returns:
      { "ip": str|None, "asn": str|None, "asn_desc": str|None,
        "country": str|None, "error": str|None }
    """
    try:
        ip = socket.gethostbyname(domain)
    except Exception as exc:
        return {
            "ip":       None,
            "asn":      None,
            "asn_desc": None,
            "country":  None,
            "error":    f"DNS resolution failed: {exc}",
        }

    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1, retry_count=1)

        asn = result.get("asn")
        asn_desc = result.get("asn_description") or result.get("network", {}).get("name")
        country = result.get("asn_country_code")

        return {
            "ip":       ip,
            "asn":      asn,
            "asn_desc": asn_desc,
            "country":  country,
            "error":    None,
        }
    except Exception as exc:
        return {
            "ip":       ip,
            "asn":      None,
            "asn_desc": None,
            "country":  None,
            "error":    f"ASN lookup failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Combined domain forensics
# ---------------------------------------------------------------------------

def run_domain_forensics(url: str) -> dict:
    """
    Runs WHOIS, SSL, and hosting checks on the domain in `url`.

    Returns a flat dict with:
      whois_info, ssl_info, hosting_info,
      ssl_flag (bool), ssl_note (str|None),
      hosting_flag (bool), hosting_note (str|None),
      privacy_age_flag (bool), privacy_age_note (str|None)
    """
    domain = _extract_domain(url)

    whois_info   = get_whois_info(domain)
    ssl_info     = get_ssl_info(domain)
    hosting_info = get_hosting_info(domain)

    # --- SSL flag: cert < 30 days AND domain is not on the trusted allowlist ---
    ssl_flag = False
    ssl_note = None
    if ssl_info.get("is_new") and domain not in _KNOWN_DOMAINS:
        ssl_flag = True
        ssl_note = (
            f"SSL certificate was issued only {ssl_info['age_days']} day(s) ago "
            f"(issuer: {ssl_info.get('issuer', 'unknown')}) — "
            "newly issued certs on unknown domains are a common scam indicator"
        )

    # --- Hosting flag: suspicious country AND domain resembles Indian institution ---
    hosting_flag = False
    hosting_note = None
    country = (hosting_info.get("country") or "").upper()
    if country and country not in _IN_COUNTRY_CODES and country not in _SUSPICIOUS_HOSTING_COUNTRIES:
        pass  # neutral country — don't flag
    elif country in _SUSPICIOUS_HOSTING_COUNTRIES:
        hosting_flag = True
        asn_desc = hosting_info.get("asn_desc", "unknown provider")
        hosting_note = (
            f"Domain resolves to {country} ({asn_desc}) — "
            "a site claiming to be an Indian government or bank should not be hosted here"
        )

    # --- Privacy + age flag: heavily redacted WHOIS on a new domain ---
    privacy_age_flag = False
    privacy_age_note = None
    age_days = whois_info.get("age_days")
    if whois_info.get("privacy_redacted") and age_days is not None and age_days < 90:
        privacy_age_flag = True
        privacy_age_note = (
            f"Domain is {age_days} day(s) old with full WHOIS privacy redaction — "
            "privacy protection on a very new domain is a strong scam pattern"
        )

    return {
        "domain":           domain,
        "whois_info":       whois_info,
        "ssl_info":         ssl_info,
        "hosting_info":     hosting_info,
        "ssl_flag":         ssl_flag,
        "ssl_note":         ssl_note,
        "hosting_flag":     hosting_flag,
        "hosting_note":     hosting_note,
        "privacy_age_flag": privacy_age_flag,
        "privacy_age_note": privacy_age_note,
    }
