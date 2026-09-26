"""
url_check.py — Runs three independent checks on an extracted URL:
  1. Allowlist / lookalike check against known-safe domains
  2. Domain age check via python-whois (< 90 days → suspicious)
  3. Reputation check via Google Safe Browsing + VirusTotal APIs
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


def _is_lookalike(domain: str, known_domains: list[str]) -> tuple[bool, str]:
    """
    Returns (True, matched_domain) if `domain` looks suspiciously similar
    to a known-safe domain but is NOT an exact match.
    Uses difflib ratio > 0.75 as the similarity threshold.
    """
    # Strip TLD-ish suffixes for comparison — compare just the SLD part
    for known in known_domains:
        if domain == known:
            return False, known  # exact match — it IS the real domain
        ratio = difflib.SequenceMatcher(None, domain, known).ratio()
        if ratio > 0.75:
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
# Main entry point — run all URL checks
# ---------------------------------------------------------------------------

def run_url_checks(url: str) -> dict:
    """
    Runs all three URL checks and returns a combined dict:
    {
      "allowlist": { ... },
      "age": { ... },
      "reputation_flagged": bool,
      "reputation_reasons": [str, ...]
    }
    """
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
        "allowlist": allowlist_result,
        "age": age_result,
        "reputation_flagged": bool(reputation_reasons),
        "reputation_reasons": reputation_reasons,
    }
