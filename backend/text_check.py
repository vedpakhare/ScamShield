"""
text_check.py — Sends the raw message to Gemini for scam detection.
Returns: { "is_suspicious": bool, "reasons": [...], "confidence": 0-100 }

Uses the current google-genai SDK (google.genai).
"""

import os
import json
from google import genai
from google.genai import types

# System prompt that instructs Gemini to act as a scam detection analyst
SYSTEM_PROMPT = (
    "You are a scam detection analyst. Given a message, identify manipulation patterns: "
    "urgency/threats, OTP or PIN requests, mismatched sender identity vs stated purpose "
    "(e.g. an electricity company issuing a traffic fine), 'do not share' phrasing, "
    "unsolicited prize/loan/refund offers. "
    'Return strict JSON: {"is_suspicious": bool, "reasons": [list of short strings], "confidence": 0-100}.'
)


def analyze_text(message: str) -> dict:
    """
    Calls the Gemini API to analyze the message for scam indicators.
    Returns a dict with keys: is_suspicious (bool), reasons (list), confidence (int).
    Falls back to a safe default if the API call fails.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "is_suspicious": False,
            "reasons": ["Gemini API key not configured — text analysis skipped."],
            "confidence": 0,
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

        # Strip markdown code fences in case they appear despite response_mime_type
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        result = json.loads(raw)

        # Normalise keys so callers always get consistent types
        return {
            "is_suspicious": bool(result.get("is_suspicious", False)),
            "reasons": result.get("reasons", []),
            "confidence": int(result.get("confidence", 0)),
        }

    except Exception as exc:
        # Don't crash the whole request — return a graceful fallback
        return {
            "is_suspicious": False,
            "reasons": [f"Text analysis failed: {exc}"],
            "confidence": 0,
        }
