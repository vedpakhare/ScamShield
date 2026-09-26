"""
verdict.py — Combines text check + URL check results into a final verdict.

Scoring rules:
  +40  text check flagged as suspicious (AI text analysis)
  +15  URL structure is suspicious (IP address, shortener, excessive subdomains, misleading path)
  +25  URL domain is a lookalike of a known-safe domain
  +20  URL domain is unknown (not on allowlist, not a lookalike)
  +20  URL domain registered < 90 days ago
  +10  URL flagged by reputation APIs (Safe Browsing / VirusTotal)

  Note: lookalike and unknown are mutually exclusive (+25 vs +20); max for URL domain = 25.

Final verdict thresholds:
  score >= 70  → HIGH RISK
  score 35–69  → MEDIUM RISK
  score < 35   → LIKELY SAFE

The response includes a "score_breakdown" list so every point is explainable.
"""

# Human-readable labels for the 8 text categories
_CATEGORY_LABELS = {
    "urgency_threats":         "Urgency / threats",
    "otp_pin_request":         "OTP or credential request",
    "brand_impersonation":     "Brand/agency impersonation",
    "sender_mismatch":         "Sender identity mismatch",
    "grammar_tone":            "Suspicious grammar / tone",
    "unusual_payment_channel": "Unusual payment channel",
    "unsolicited_offer":       "Unsolicited offer",
    "do_not_share":            '"Do not share" phrasing',
}


def build_verdict(
    text_result: dict,
    url_found: str | None,
    url_checks: dict | None,
    email_auth: dict | None = None,
    domain_forensics: dict | None = None,
) -> dict:
    """
    Parameters
    ----------
    text_result : dict
        Output from text_check.analyze_text()
    url_found : str | None
        The first URL extracted from the message, or None.
    url_checks : dict | None
        Output from url_check.run_url_checks(), or None if no URL was found.
    email_auth : dict | None
        Output from email_check.check_email_auth(), or None.
    domain_forensics : dict | None
        Output from domain_forensics.run_domain_forensics(), or None.

    Returns
    -------
    dict with keys:
        verdict, score, score_breakdown, reasons, url_found, url_status
    """
    score = 0
    score_breakdown: list[dict] = []   # [{signal, points, detail}]
    reasons: list[str] = []

    # ------------------------------------------------------------------
    # Text analysis contribution
    # ------------------------------------------------------------------
    text_suspicious = text_result.get("is_suspicious", False)
    categories = text_result.get("categories", {})

    if text_suspicious:
        score += 40
        # Surface which specific categories fired
        fired = [
            _CATEGORY_LABELS[k]
            for k, v in categories.items()
            if v and k in _CATEGORY_LABELS
        ]
        detail = ", ".join(fired) if fired else "multiple patterns"
        score_breakdown.append({
            "signal": "AI text analysis",
            "points": 40,
            "detail": f"Flagged: {detail}",
        })
        reasons.extend(text_result.get("reasons", []))
    else:
        # Surface non-error reasons even when not flagged (informational)
        for r in text_result.get("reasons", []):
            if not any(w in r.lower() for w in ("failed", "skipped", "not configured")):
                reasons.append(r)

    # ------------------------------------------------------------------
    # URL analysis contribution
    # ------------------------------------------------------------------
    url_status: str | None = None

    if url_found and url_checks:
        structure = url_checks.get("structure", {})
        allowlist = url_checks.get("allowlist", {})
        age       = url_checks.get("age", {})
        rep_flagged  = url_checks.get("reputation_flagged", False)
        rep_reasons  = url_checks.get("reputation_reasons", [])

        # -- URL structure --
        if structure.get("suspicious"):
            score += 15
            struct_reasons = structure.get("reasons", [])
            score_breakdown.append({
                "signal": "URL structure",
                "points": 15,
                "detail": "; ".join(struct_reasons) if struct_reasons else "Suspicious URL patterns",
            })
            reasons.extend(struct_reasons)
            url_status = "suspicious"

        # -- Allowlist / lookalike --
        al_status = allowlist.get("status")  # "known-safe" | "lookalike" | "unknown"

        if al_status == "known-safe":
            url_status = url_status or "known-safe"
            score_breakdown.append({
                "signal": "Domain allowlist",
                "points": 0,
                "detail": f"Domain matches known-safe entry '{allowlist.get('matched_domain', '')}'",
            })
        elif al_status == "lookalike":
            score += 25
            url_status = "suspicious"
            reason_txt = allowlist.get("reason", "Domain resembles a known-safe domain")
            score_breakdown.append({
                "signal": "Domain lookalike",
                "points": 25,
                "detail": reason_txt,
            })
            reasons.append(reason_txt)
        else:  # unknown
            score += 20
            url_status = url_status or "unknown"
            score_breakdown.append({
                "signal": "Domain unknown",
                "points": 20,
                "detail": "Domain not found in trusted allowlist",
            })
            reasons.append("URL domain not in trusted allowlist")

        # -- Domain age --
        if age.get("is_new"):
            score += 20
            age_reason = age.get("reason", "Domain is very recently registered")
            score_breakdown.append({
                "signal": "Domain age",
                "points": 20,
                "detail": age_reason,
            })
            reasons.append(age_reason)

        # -- Reputation --
        if rep_flagged:
            score += 10
            score_breakdown.append({
                "signal": "Reputation APIs",
                "points": 10,
                "detail": "; ".join(rep_reasons),
            })
            reasons.extend(rep_reasons)
            url_status = "suspicious"

    # ------------------------------------------------------------------
    # Email authentication contribution (Feature 2)
    # ------------------------------------------------------------------
    if email_auth and not email_auth.get("error"):
        ea_risk = email_auth.get("overall_risk", "low")
        ea_reasons = email_auth.get("risk_reasons", [])
        if ea_risk in ("medium", "high"):
            pts = 10 if ea_risk == "medium" else 15
            score += pts
            score_breakdown.append({
                "signal": "Email authentication",
                "points": pts,
                "detail": "; ".join(ea_reasons) if ea_reasons else f"Email auth risk: {ea_risk}",
            })
            reasons.extend(ea_reasons)

    # ------------------------------------------------------------------
    # Domain forensics contribution (Feature 3)
    # ------------------------------------------------------------------
    if domain_forensics and not domain_forensics.get("error"):
        # SSL cert recently issued
        if domain_forensics.get("ssl_flag"):
            score += 15
            score_breakdown.append({
                "signal": "SSL certificate",
                "points": 15,
                "detail": domain_forensics.get("ssl_note", "Certificate recently issued"),
            })
            reasons.append(domain_forensics.get("ssl_note", "SSL certificate recently issued"))

        # Hosting country mismatch
        if domain_forensics.get("hosting_flag"):
            score += 15
            score_breakdown.append({
                "signal": "Hosting location",
                "points": 15,
                "detail": domain_forensics.get("hosting_note", "Suspicious hosting country"),
            })
            reasons.append(domain_forensics.get("hosting_note", "Suspicious hosting country"))

    # ------------------------------------------------------------------
    # Cap score, derive verdict label
    # ------------------------------------------------------------------
    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 35:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LIKELY SAFE"

    # De-duplicate reasons, preserve order
    seen: set[str] = set()
    unique_reasons: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    return {
        "verdict":         verdict,
        "score":           score,
        "score_breakdown": score_breakdown,
        "reasons":         unique_reasons,
        "url_found":       url_found,
        "url_status":      url_status,
    }
