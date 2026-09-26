"""
text_check.py — Sends the raw message to Gemini for scam detection.

Returns a richer per-category breakdown:
{
  "is_suspicious": bool,
  "confidence": 0-100,
  "categories": {
    "urgency_threats":         bool,
    "otp_pin_request":         bool,
    "brand_impersonation":     bool,
    "sender_mismatch":         bool,
    "grammar_tone":            bool,
    "unusual_payment_channel": bool,
    "unsolicited_offer":       bool,
    "do_not_share":            bool
  },
  "reasons": [list of short explanation strings]
}

Uses the current google-genai SDK (google.genai).
"""

import os
import json
from google import genai
from google.genai import types

# ---------------------------------------------------------------------------
# System prompt — expanded with per-category instructions
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a professional scam detection analyst. Analyze the given message for fraud indicators.

Return ONLY valid JSON in exactly this structure — no prose, no markdown:
{
  "is_suspicious": <true|false>,
  "confidence": <integer 0-100>,
  "categories": {
    "urgency_threats":         <true|false>,
    "otp_pin_request":         <true|false>,
    "brand_impersonation":     <true|false>,
    "sender_mismatch":         <true|false>,
    "grammar_tone":            <true|false>,
    "unusual_payment_channel": <true|false>,
    "unsolicited_offer":       <true|false>,
    "do_not_share":            <true|false>
  },
  "reasons": [<list of short, specific explanation strings>]
}

Category definitions:
- urgency_threats: Artificial time pressure, threat of disconnection/legal action/account closure if immediate action not taken.
- otp_pin_request: Asks for OTP, PIN, CVV, password, or any authentication credential.
- brand_impersonation: Claims to be from a specific well-known brand, bank (SBI, HDFC, ICICI, Paytm, etc.) or government agency (MSEDCL, UIDAI, Income Tax, etc.) without evidence of legitimacy.
- sender_mismatch: The claimed sender identity does not match the stated purpose (e.g. electricity company sending traffic fine, bank asking for KYC via WhatsApp).
- grammar_tone: Unusual grammar, awkward phrasing, inconsistent capitalisation, or machine-translated tone typical of scam messages.
- unusual_payment_channel: Requests payment via gift cards, cryptocurrency, UPI to personal/random number, wire transfer to unknown account, or any channel that avoids official systems.
- unsolicited_offer: Unprompted offer of prize, lottery win, loan, cashback, refund, or job — especially requiring upfront payment or personal details.
- do_not_share: Contains the phrase "do not share", "share with no one", or equivalent intended to block the target from seeking verification.

Set is_suspicious=true if ANY category is true. Confidence reflects overall certainty. Reasons should be concrete and specific (mention actual text from the message when relevant), not generic."""


# ---------------------------------------------------------------------------
# Fallback category structure (all false)
# ---------------------------------------------------------------------------
_EMPTY_CATEGORIES = {
    "urgency_threats":         False,
    "otp_pin_request":         False,
    "brand_impersonation":     False,
    "sender_mismatch":         False,
    "grammar_tone":            False,
    "unusual_payment_channel": False,
    "unsolicited_offer":       False,
    "do_not_share":            False,
}


def analyze_text(message: str) -> dict:
    """
    Calls the Gemini API to analyze the message for scam indicators.

    Returns:
      {
        "is_suspicious": bool,
        "confidence": int,
        "categories": { <8 category booleans> },
        "reasons": list[str]
      }
    Falls back to a safe default if the API call fails or key is missing.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "is_suspicious": False,
            "confidence": 0,
            "categories": _EMPTY_CATEGORIES.copy(),
            "reasons": ["Gemini API key not configured — text analysis skipped."],
        }

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=message,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
            ),
        )

        raw = response.text.strip()

        # Strip markdown fences defensively
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        result = json.loads(raw)

        # Merge returned categories with the fallback so callers always see
        # all 8 keys even if Gemini omits some.
        categories = _EMPTY_CATEGORIES.copy()
        for k, v in result.get("categories", {}).items():
            if k in categories:
                categories[k] = bool(v)

        return {
            "is_suspicious": bool(result.get("is_suspicious", False)),
            "confidence": int(result.get("confidence", 0)),
            "categories": categories,
            "reasons": result.get("reasons", []),
        }

    except Exception as exc:
        return {
            "is_suspicious": False,
            "confidence": 0,
            "categories": _EMPTY_CATEGORIES.copy(),
            "reasons": [f"Text analysis failed: {exc}"],
        }
