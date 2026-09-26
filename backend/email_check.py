"""
email_check.py — SPF, DKIM (selector discovery), and DMARC DNS record checks.

Uses dnspython to look up public TXT records — no paid API needed.
All lookups are wrapped in try/except with a 5-second timeout.

Returns:
{
  "domain": str,
  "spf":   { "found": bool, "record": str|None, "pass": bool, "note": str|None },
  "dmarc": { "found": bool, "record": str|None, "policy": str|None, "note": str|None },
  "dkim":  { "checked": bool, "found": bool, "selector": str|None, "note": str|None },
  "overall_risk": "low" | "medium" | "high",
  "risk_reasons": [str, ...]
}
"""

import dns.resolver
import dns.exception

# DNS timeout in seconds — generous enough to handle slow servers
_DNS_TIMEOUT = 5.0

# Common DKIM selectors to probe — limited to the most universal ones
# to avoid slow timeouts (each is a DNS round-trip)
_COMMON_DKIM_SELECTORS = ["default", "google", "mail", "selector1", "dkim"]


def _query_txt(name: str) -> list[str]:
    """
    Queries DNS TXT records for `name`.
    Returns a list of record strings (decoded), or an empty list on failure.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    try:
        answers = resolver.resolve(name, "TXT")
        results = []
        for rdata in answers:
            # Each TXT record can have multiple strings — join them
            record = "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            results.append(record)
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        raise TimeoutError(f"DNS timeout querying {name}")
    except Exception:
        return []


# ---------------------------------------------------------------------------
# SPF check
# ---------------------------------------------------------------------------

def check_spf(domain: str) -> dict:
    """
    Looks for a 'v=spf1' TXT record on the domain.
    Returns status + the raw record string.
    """
    try:
        records = _query_txt(domain)
    except TimeoutError as e:
        return {"found": False, "record": None, "pass": False, "note": str(e)}

    for r in records:
        if r.lower().startswith("v=spf1"):
            # An ~all or -all is a real SPF record; ?all or no qualifier is weak
            spf_pass = ("~all" in r or "-all" in r)
            return {
                "found": True,
                "record": r,
                "pass": spf_pass,
                "note": None if spf_pass else "SPF record exists but has a weak/permissive policy",
            }

    return {
        "found": False,
        "record": None,
        "pass": False,
        "note": "No SPF record found — anyone can send email claiming this domain",
    }


# ---------------------------------------------------------------------------
# DMARC check
# ---------------------------------------------------------------------------

def check_dmarc(domain: str) -> dict:
    """
    Looks for a DMARC policy at _dmarc.<domain>.
    Returns status, policy (none/quarantine/reject), and the raw record.
    """
    try:
        records = _query_txt(f"_dmarc.{domain}")
    except TimeoutError as e:
        return {"found": False, "record": None, "policy": None, "note": str(e)}

    for r in records:
        if "v=dmarc1" in r.lower():
            # Extract the p= policy tag
            policy = None
            for part in r.split(";"):
                p = part.strip()
                if p.lower().startswith("p="):
                    policy = p[2:].strip().lower()
                    break

            weak = policy in (None, "none")
            return {
                "found": True,
                "record": r,
                "policy": policy,
                "note": (
                    "DMARC policy is 'none' — no enforcement, easy to spoof"
                    if weak else None
                ),
            }

    return {
        "found": False,
        "record": None,
        "policy": None,
        "note": "No DMARC record found — domain has no email authentication policy",
    }


# ---------------------------------------------------------------------------
# DKIM check (selector probe)
# ---------------------------------------------------------------------------

def check_dkim(domain: str) -> dict:
    """
    Probes common DKIM selectors at <selector>._domainkey.<domain>.
    Does not try all selectors — just checks if any common one exists.
    """
    for selector in _COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        try:
            records = _query_txt(name)
        except TimeoutError:
            continue  # timeout on one selector — keep trying
        for r in records:
            if "v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower():
                return {
                    "checked": True,
                    "found": True,
                    "selector": selector,
                    "note": None,
                }

    return {
        "checked": True,
        "found": False,
        "selector": None,
        "note": (
            "No DKIM record found with common selectors — "
            "legitimate senders typically publish DKIM keys"
        ),
    }


# ---------------------------------------------------------------------------
# Combined email auth check
# ---------------------------------------------------------------------------

def check_email_auth(domain: str) -> dict:
    """
    Runs SPF + DMARC + DKIM checks and returns a combined result with
    an overall risk rating and list of risk reasons.

    Parameters
    ----------
    domain : the sender's email domain (e.g. "hdfc-bank-notice.com")

    Returns
    -------
    {
      "domain": str,
      "spf":   { ... },
      "dmarc": { ... },
      "dkim":  { ... },
      "overall_risk": "low" | "medium" | "high",
      "risk_reasons": [str, ...]
    }
    """
    spf   = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim  = check_dkim(domain)

    risk_reasons: list[str] = []
    risk_points = 0

    # SPF absent or weak
    if not spf["found"]:
        risk_reasons.append(f"No SPF record on {domain}")
        risk_points += 1
    elif not spf["pass"]:
        risk_reasons.append(f"Weak SPF policy on {domain}")
        risk_points += 1

    # DMARC absent or weak
    if not dmarc["found"]:
        risk_reasons.append(f"No DMARC record on {domain}")
        risk_points += 1
    elif dmarc.get("policy") == "none":
        risk_reasons.append(f"DMARC policy is 'none' (not enforced) on {domain}")
        risk_points += 1

    # DKIM absent
    if dkim.get("checked") and not dkim.get("found"):
        risk_reasons.append(f"No DKIM key found for {domain}")
        risk_points += 1

    if risk_points == 0:
        overall = "low"
    elif risk_points <= 2:
        overall = "medium"
    else:
        overall = "high"

    return {
        "domain": domain,
        "spf":          spf,
        "dmarc":        dmarc,
        "dkim":         dkim,
        "overall_risk": overall,
        "risk_reasons": risk_reasons,
    }
