"""
main.py — FastAPI application for ScamShield.

Endpoint: POST /analyze — single message analysis

Input:  { "message": "...", "message_type": "sms"|"email", "sender_email": "..." }
Output: { verdict, score, score_breakdown, reasons, url_found, url_status,
          sender_analysis, email_auth, domain_forensics, cached }

Features:
  - message_type: "sms" always shows sender-spoofing disclaimer.
                  "email" triggers SPF/DKIM/DMARC checks on sender domain.
  - In-memory result cache (TTL = 1 hour).
"""

import re
import os
import time
import hashlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from text_check import analyze_text
from url_check import run_url_checks
from verdict import build_verdict
from sender_check import analyze_sender

# Load .env file if present (for local development)
load_dotenv()

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------
# Structure: { cache_key: {"result": dict, "expires_at": float} }
_CACHE: dict[str, dict] = {}
_CACHE_TTL_SECONDS = 3600  # 1 hour


def _cache_key(message: str) -> str:
    """SHA-256 of the normalised message — avoids storing raw PII as keys."""
    return hashlib.sha256(message.lower().strip().encode()).hexdigest()


def _cache_get(key: str) -> dict | None:
    """Return cached result if it exists and has not expired, else None."""
    entry = _CACHE.get(key)
    if entry and entry["expires_at"] > time.time():
        return entry["result"]
    # Expired — remove it
    if entry:
        del _CACHE[key]
    return None


def _cache_set(key: str, result: dict) -> None:
    """Store result in cache with a TTL expiry timestamp."""
    _CACHE[key] = {
        "result": result,
        "expires_at": time.time() + _CACHE_TTL_SECONDS,
    }


def _cache_evict_expired() -> None:
    """Purge all expired entries to prevent unbounded memory growth."""
    now = time.time()
    expired = [k for k, v in _CACHE.items() if v["expires_at"] <= now]
    for k in expired:
        del _CACHE[k]


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle hook."""
    print("ScamShield backend starting up…")
    yield
    print("ScamShield backend shutting down.")


app = FastAPI(
    title="ScamShield",
    description="Scam message and URL verifier API",
    version="1.1.0",
    lifespan=lifespan,
)

# Allow all origins so the static frontend (file://) can call the API freely.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    message: str
    message_type: str = "sms"       # "sms" | "email"
    sender_email: str | None = None  # only used when message_type == "email"


# ---------------------------------------------------------------------------
# URL extraction helper
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>)]+|"           # standard http(s) URLs
    r"(?:www\.)[a-zA-Z0-9\-]+\.[a-z]{2,}(?:/[^\s]*)?",  # bare www. links
    re.IGNORECASE,
)

def extract_first_url(text: str) -> str | None:
    """Return the first URL found in `text`, or None."""
    match = _URL_PATTERN.search(text)
    if match:
        url = match.group(0).rstrip(".,;")
        if not url.startswith("http"):
            url = "https://" + url
        return url
    return None


# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------

def _run_analysis(message: str, message_type: str, sender_email: str | None) -> dict:
    """
    Core analysis pipeline shared by /analyze and /analyze-batch.
    Returns the full result dict (without the 'cached' flag).
    """
    # F1 — Sender analysis
    sender_result = analyze_sender(message_type, sender_email)

    # F2 — Email authentication (lazy import so missing dnspython doesn't crash on startup)
    email_auth = None
    if message_type == "email" and sender_result.get("sender_domain"):
        try:
            from email_check import check_email_auth
            email_auth = check_email_auth(sender_result["sender_domain"])
        except ImportError:
            email_auth = {"error": "email_check module not available"}

    # 1. Extract URL
    url_found = extract_first_url(message)

    # 2. Text analysis via Gemini
    text_result = analyze_text(message)

    # 3. URL checks (only if a URL was detected)
    url_checks = None
    domain_forensics = None
    if url_found:
        url_checks = run_url_checks(url_found)
        # F3 — Domain forensics (lazy import)
        try:
            from domain_forensics import run_domain_forensics
            domain_forensics = run_domain_forensics(url_found)
        except ImportError:
            domain_forensics = None

    # 4. Build the final verdict (passes email_auth + domain_forensics for scoring)
    result = build_verdict(
        text_result, url_found, url_checks,
        email_auth=email_auth,
        domain_forensics=domain_forensics,
    )

    result["text_categories"]  = text_result.get("categories", {})
    result["sender_analysis"]  = sender_result
    result["email_auth"]       = email_auth
    result["domain_forensics"] = domain_forensics

    return result


@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Analyzes a single message for scam indicators.
    Returns cached result if the same inputs were seen within the last hour.
    """
    message      = request.message.strip()
    message_type = request.message_type.lower().strip() or "sms"
    sender_email = (request.sender_email or "").strip() or None

    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    # Cache key includes all inputs so different types never collide
    cache_input = f"{message_type}|{sender_email or ''}|{message}"
    key = _cache_key(cache_input)
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "cached": True}

    _cache_evict_expired()

    result = _run_analysis(message, message_type, sender_email)
    result["cached"] = False
    _cache_set(key, result)
    return result


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "cache_entries": len(_CACHE)}
