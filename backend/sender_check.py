"""
sender_check.py — Handles sender identity analysis for SMS and email.

For SMS:
  Returns an honest disclosure that SMS sender IDs cannot be independently
  verified — they are trivially spoofed and the disclaimer is always shown.

For Email:
  Extracts the sender domain from the provided email address so that
  Feature 2 (email_check.py) can run DNS authentication checks on it.

Returns a dict that is passed through to the final report as "sender_analysis".
"""

import re


# Regex to pull the domain out of an email address
_EMAIL_DOMAIN_RE = re.compile(r"@([\w.\-]+)$")

# Standard disclaimer shown for every SMS analysis — this is intentional UX,
# not an error message.
SMS_DISCLAIMER = (
    "Sender ID cannot be independently verified for SMS — "
    "this field is commonly spoofed in scam messages. "
    "Do not trust the sender name shown on your phone."
)


def analyze_sender(message_type: str, sender_email: str | None) -> dict:
    """
    Parameters
    ----------
    message_type : "sms" | "email"
    sender_email : the full address pasted by the user (email mode only),
                   or None / empty string for SMS.

    Returns
    -------
    {
      "type": "sms" | "email",
      "disclaimer": str | None,        # always set for SMS, None for email
      "sender_email": str | None,      # raw input, email mode only
      "sender_domain": str | None,     # extracted domain, email mode only
      "error": str | None,             # set if email address is malformed
    }
    """
    if message_type == "sms":
        return {
            "type": "sms",
            "disclaimer": SMS_DISCLAIMER,
            "sender_email": None,
            "sender_domain": None,
            "error": None,
        }

    # --- email mode ---
    raw = (sender_email or "").strip()

    if not raw:
        return {
            "type": "email",
            "disclaimer": None,
            "sender_email": None,
            "sender_domain": None,
            "error": "No sender email address provided.",
        }

    match = _EMAIL_DOMAIN_RE.search(raw)
    if not match:
        return {
            "type": "email",
            "disclaimer": None,
            "sender_email": raw,
            "sender_domain": None,
            "error": f"Could not extract domain from '{raw}' — is it a valid email address?",
        }

    domain = match.group(1).lower()
    return {
        "type": "email",
        "disclaimer": None,
        "sender_email": raw,
        "sender_domain": domain,
        "error": None,
    }
