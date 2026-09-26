"""
url_check.py — Runs four independent checks on an extracted URL:
  1. URL structure check (IP address, excessive subdomains, shorteners, misleading paths)
  2. Allowlist / lookalike check against known-safe domains
  3. Domain age check via python-whois (< 90 days → suspicious)
  4. Reputation check via Google Safe Browsing + VirusTotal APIs
"""

import os
import json
import re
import difflib
import datetime
import requests
import whois
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the allowlist of known-safe domains from known_domains.json
# ---------------------------------------------------------------------------
_ALLOWLIST_PATH = Path(__file__).parent / "known_domains.json"

def _load_allowlist() -> list[str]:
    try:
        with open(_ALLOWLIST_PATH) as f:
            return json.load(f).get("allowlist", [])
    except Exception:
        return []

KNOWN_DOMAINS: list[str] = _load_allowlist()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Strip scheme, www., and path to get the bare domain."""
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)
    domain = url.split("/")[0].split("?")[0].split("#")[0]
    return domain.lower().strip()


# Two-part TLD suffixes common in Indian domains
_TWO_PART_TLDS = {
    "gov.in", "co.in", "org.in", "net.in", "edu.in", "ac.in",
    "nic.in", "res.in", "mil.in",
}

def _sld(domain: str) -> str:
    """
    Extract the meaningful brand name from a domain.
    Handles two-part TLDs like .gov.in, .co.in correctly.
    e.g. parivahan.gov.in  → "parivahan"
         mparivahanofficial.com → "mparivahanofficial"
         sbi.co.in          → "sbi"
    """
    parts = domain.split(".")
    if len(parts) >= 3:
        two_part = ".".join(parts[-2:])
        if two_part in _TWO_PART_TLDS:
            return parts[-3]   # brand is one level above the two-part TLD
    return parts[-2] if len(parts) >= 2 else parts[0]


def _is_lookalike(domain: str, known_domains: list[str]) -> tuple[bool, str]:
    """
    Returns (True, matched_domain) if `domain` looks suspiciously similar
    to a known-safe domain but is NOT an exact match.

    Three checks (any one triggers):
      1. difflib ratio > 0.75 on the full domain string
      2. The known domain's SLD keyword appears embedded inside the suspicious domain
         e.g. "parivahan" inside "mparivahanofficial.com"
      3. The suspicious domain's SLD is a substring of a known domain's SLD
         (catches prefixed/suffixed variations)
    """
    suspicious_sld = _sld(domain)

    for known in known_domains:
        if domain == known:
            return False, known  # exact match — it IS the real domain

        # Check 1: string similarity on full domain
        ratio = difflib.SequenceMatcher(None, domain, known).ratio()
        if ratio > 0.75:
            return True, known

        known_sld = _sld(known)

        # Check 2: known brand name is embedded inside the suspicious domain
        # e.g. "parivahan" in "mparivahanofficial.com" → flag
        if len(known_sld) >= 5 and known_sld in domain:
            return True, known

        # Check 3: suspicious SLD contains or matches the known SLD closely
        if len(suspicious_sld) >= 5 and suspicious_sld in known_sld:
            return True, known

    return False, ""


# ---------------------------------------------------------------------------
# Check 1 — Allowlist / lookalike
# ---------------------------------------------------------------------------

def check_allowlist(url: str) -> dict:
    """
    Returns:
      { "status": "known-safe" | "lookalike" | "unknown",
        "reason": str or None,
        "matched_domain": str or None }
    """
    domain = _extract_domain(url)

    if domain in KNOWN_DOMAINS:
        return {"status": "known-safe", "reason": None, "matched_domain": domain}

    is_lookalike, matched = _is_lookalike(domain, KNOWN_DOMAINS)
    if is_lookalike:
        return {
            "status": "lookalike",
            "reason": f"Domain '{domain}' closely resembles known-safe domain '{matched}'",
            "matched_domain": matched,
        }

    return {"status": "unknown", "reason": None, "matched_domain": None}


# ---------------------------------------------------------------------------
# Check 2 — Domain age via WHOIS
# ---------------------------------------------------------------------------

def check_domain_age(url: str) -> dict:
    """
    Returns:
      { "age_days": int or None, "is_new": bool, "reason": str or None }
    New is defined as < 90 days old.
    """
    domain = _extract_domain(url)
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        # python-whois sometimes returns a list
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return {"age_days": None, "is_new": False, "reason": "WHOIS creation date unavailable"}

        # Ensure timezone-naive comparison
        if hasattr(creation, "tzinfo") and creation.tzinfo is not None:
            creation = creation.replace(tzinfo=None)

        age_days = (datetime.datetime.utcnow() - creation).days

        if age_days < 90:
            return {
                "age_days": age_days,
                "is_new": True,
                "reason": f"Domain registered only {age_days} day(s) ago",
            }
        return {"age_days": age_days, "is_new": False, "reason": None}

    except Exception as exc:
        # WHOIS lookup can fail for many reasons — don't crash
        return {"age_days": None, "is_new": False, "reason": f"WHOIS lookup failed: {exc}"}


# ---------------------------------------------------------------------------
# Check 3a — Google Safe Browsing
# ---------------------------------------------------------------------------

def check_safe_browsing(url: str) -> dict:
    """
    Returns { "flagged": bool, "reason": str or None }
    Skips gracefully on missing key or API error.
    """
    api_key = os.getenv("SAFE_BROWSING_KEY")
    if not api_key:
        return {"flagged": False, "reason": None}  # silently skip

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "scamshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("matches"):
            return {"flagged": True, "reason": "Flagged by Google Safe Browsing"}
        return {"flagged": False, "reason": None}
    except Exception:
        return {"flagged": False, "reason": None}


# ---------------------------------------------------------------------------
# Check 3b — VirusTotal
# ---------------------------------------------------------------------------

def check_virustotal(url: str) -> dict:
    """
    Returns { "flagged": bool, "reason": str or None }
    Skips gracefully on missing key or API error.
    """
    api_key = os.getenv("VIRUSTOTAL_KEY")
    if not api_key:
        return {"flagged": False, "reason": None}  # silently skip

    import base64
    # VirusTotal URL ID is base64url of the URL (no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(endpoint, headers=headers, timeout=5)
        if resp.status_code == 404:
            # URL not in VirusTotal database yet
            return {"flagged": False, "reason": None}
        resp.raise_for_status()
        data = resp.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            return {
                "flagged": True,
                "reason": f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections",
            }
        return {"flagged": False, "reason": None}
    except Exception:
        return {"flagged": False, "reason": None}


# ---------------------------------------------------------------------------
# Check 0 — URL structure analysis (no external API needed)
# ---------------------------------------------------------------------------

# Known URL shortener hostnames
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "short.io", "cutt.ly", "tiny.cc",
    "shorte.st", "adf.ly", "bc.vc", "lnkd.in", "dlvr.it",
}

# Paths that are commonly spoofed to look legitimate
_MISLEADING_PATH_SEGMENTS = [
    "secure-login", "secure_login", "login-secure", "verify-account",
    "account-verify", "confirm-identity", "update-kyc", "kyc-update",
    "pay-now", "payment-verify", "bank-login", "netbanking",
    "official-portal", "govt-portal", "e-challan-pay",
]


def check_url_structure(url: str) -> dict:
    """
    Inspects the URL itself for suspicious structural patterns — no network call.

    Returns:
      {
        "suspicious": bool,
        "reasons": list[str],   # empty if clean
        "flags": {
          "is_ip_address":       bool,
          "is_shortener":        bool,
          "excessive_subdomains": bool,
          "misleading_path":     bool,
        }
      }
    """
    reasons: list[str] = []
    flags = {
        "is_ip_address":        False,
        "is_shortener":         False,
        "excessive_subdomains": False,
        "misleading_path":      False,
    }

    # Normalise: strip scheme for domain extraction
    stripped = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    host_part = stripped.split("/")[0].split("?")[0].split("#")[0].lower()
    path_part = "/" + "/".join(stripped.split("/")[1:]) if "/" in stripped else ""

    # 1. IP address instead of domain name
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    )
    if ip_pattern.match(host_part):
        flags["is_ip_address"] = True
        reasons.append(f"URL uses a raw IP address instead of a domain name ({host_part})")

    # 2. URL shortener — hides real destination
    domain_only = re.sub(r"^www\.", "", host_part)
    if domain_only in _URL_SHORTENERS:
        flags["is_shortener"] = True
        reasons.append(f"URL uses a shortener service ({domain_only}) — real destination is hidden")

    # 3. Excessive subdomains (more than 3 labels before the TLD is suspicious)
    #    e.g. login.secure.sbi.co.malicious.com
    labels = host_part.split(".")
    if len(labels) > 4:
        flags["excessive_subdomains"] = True
        reasons.append(
            f"URL has {len(labels)} subdomain levels — scammers use this to hide the real domain"
        )

    # 4. Misleading path segments
    path_lower = path_part.lower()
    for segment in _MISLEADING_PATH_SEGMENTS:
        if segment in path_lower:
            flags["misleading_path"] = True
            reasons.append(f"URL path contains suspicious segment '/{segment}/'")
            break  # report once

    return {
        "suspicious": any(flags.values()),
        "reasons": reasons,
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# Main entry point — run all URL checks
# ---------------------------------------------------------------------------

def run_url_checks(url: str) -> dict:
    """
    Runs all four URL checks and returns a combined dict:
    {
      "structure": { ... },
      "allowlist": { ... },
      "age": { ... },
      "reputation_flagged": bool,
      "reputation_reasons": [str, ...]
    }
    """
    structure_result = check_url_structure(url)
    allowlist_result = check_allowlist(url)
    age_result = check_domain_age(url)

    # Reputation checks — run both, collect reasons
    sb_result = check_safe_browsing(url)
    vt_result = check_virustotal(url)

    reputation_reasons = []
    if sb_result["flagged"] and sb_result["reason"]:
        reputation_reasons.append(sb_result["reason"])
    if vt_result["flagged"] and vt_result["reason"]:
        reputation_reasons.append(vt_result["reason"])

    return {
        "structure": structure_result,
        "allowlist": allowlist_result,
        "age": age_result,
        "reputation_flagged": bool(reputation_reasons),
        "reputation_reasons": reputation_reasons,
    }
