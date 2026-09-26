"""
main.py — FastAPI application for ScamShield.

Single endpoint: POST /analyze
Input:  { "message": "<raw text>" }
Output: { verdict, score, reasons, url_found, url_status }
"""

import re
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from text_check import analyze_text
from url_check import run_url_checks
from verdict import build_verdict

# Load .env file if present (for local development)
load_dotenv()

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
    version="1.0.0",
    lifespan=lifespan,
)

# Allow all origins so the static frontend (file://) can call the API freely.
# Restrict this in production to your actual frontend origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# URL extraction helper
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>)]+|"          # standard http(s) URLs
    r"(?:www\.)[a-zA-Z0-9\-]+\.[a-z]{2,}(?:/[^\s]*)?",  # bare www. links
    re.IGNORECASE,
)

def extract_first_url(text: str) -> str | None:
    """Return the first URL found in `text`, or None."""
    match = _URL_PATTERN.search(text)
    if match:
        url = match.group(0).rstrip(".,;")
        # Ensure it has a scheme so downstream libs work correctly
        if not url.startswith("http"):
            url = "https://" + url
        return url
    return None


# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Analyzes a message for scam indicators.
    Runs text analysis (Gemini) and, if a URL is present, URL checks in parallel logic.
    """
    message = request.message.strip()

    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    # 1. Extract URL
    url_found = extract_first_url(message)

    # 2. Text analysis via Gemini
    text_result = analyze_text(message)

    # 3. URL checks (only if a URL was detected)
    url_checks = None
    if url_found:
        url_checks = run_url_checks(url_found)

    # 4. Build and return the final verdict
    result = build_verdict(text_result, url_found, url_checks)
    return result


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}
