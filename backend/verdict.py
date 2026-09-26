"""
verdict.py — Combines text check + URL check results into a final verdict.

Scoring rules:
  +40  text check flagged as suspicious
  +30  URL domain is a lookalike or unknown (not on allowlist)
  +20  URL domain is very new (< 90 days old)
  +10  URL flagged by reputation APIs (Safe Browsing / VirusTotal)

Final verdict thresholds:
  score >= 70  → HIGH RISK
  score 35–69  → MEDIUM RISK
  score < 35   → LIKELY SAFE
"""


def build_verdict(
    text_result: dict,
    url_found: str | None,
    url_checks: dict | None,
) -> dict:
    """
    Parameters
    ----------
    text_result : dict
        Output from text_check.analyze_text()
        Keys: is_suspicious (bool), reasons (list[str]), confidence (int)
    url_found : str | None
        The first URL extracted from the message, or None.
    url_checks : dict | None
        Output from url_check.run_url_checks(), or None if no URL was found.

    Returns
    -------
    dict with keys: verdict, score, reasons, url_found, url_status
    """
    score = 0
    reasons: list[str] = []

    # ------------------------------------------------------------------
    # Text analysis contribution
    # ------------------------------------------------------------------
    if text_result.get("is_suspicious"):
        score += 40
        reasons.extend(text_result.get("reasons", []))
    else:
        # Even if not flagged, surface any reasons Gemini mentioned
        for r in text_result.get("reasons", []):
            # Skip generic "failed / skipped" messages
            if "failed" not in r.lower() and "skipped" not in r.lower() and "not configured" not in r.lower():
                reasons.append(r)

    # ------------------------------------------------------------------
    # URL analysis contribution
    # ------------------------------------------------------------------
    url_status: str | None = None

    if url_found and url_checks:
        allowlist = url_checks.get("allowlist", {})
        age = url_checks.get("age", {})
        rep_flagged = url_checks.get("reputation_flagged", False)
        rep_reasons = url_checks.get("reputation_reasons", [])

        al_status = allowlist.get("status")  # "known-safe" | "lookalike" | "unknown"

        # -- Allowlist / lookalike scoring --
        if al_status == "known-safe":
            url_status = "known-safe"
            # No score bump — it's a real domain
        elif al_status == "lookalike":
            score += 30
            url_status = "suspicious"
            if allowlist.get("reason"):
                reasons.append(allowlist["reason"])
        else:  # unknown
            score += 30
            url_status = "unknown"
            reasons.append(f"URL domain not in trusted allowlist")

        # -- Domain age scoring --
        if age.get("is_new"):
            score += 20
            if age.get("reason"):
                reasons.append(age["reason"])
        elif age.get("reason") and "failed" not in age["reason"].lower():
            # Surface informational notes (e.g. "WHOIS unavailable") without scoring
            pass

        # -- Reputation scoring --
        if rep_flagged:
            score += 10
            reasons.extend(rep_reasons)
            url_status = "suspicious"

    # ------------------------------------------------------------------
    # Cap score at 100, derive verdict label
    # ------------------------------------------------------------------
    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 35:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LIKELY SAFE"

    # De-duplicate reasons while preserving order
    seen: set[str] = set()
    unique_reasons: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    return {
        "verdict": verdict,
        "score": score,
        "reasons": unique_reasons,
        "url_found": url_found,
        "url_status": url_status,
    }
