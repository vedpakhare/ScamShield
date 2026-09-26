# ScamShield

A full-stack scam message and URL verifier. Paste any suspicious SMS, email, or message and get an instant AI-powered risk assessment.

---

## Features

- **AI text analysis** — Gemini detects urgency/threats, OTP requests, mismatched sender identity, unsolicited offers.
- **Allowlist + lookalike check** — compares URLs against known-safe Indian gov/bank domains and flags similar-looking fakes.
- **Domain age check** — domains under 90 days old are flagged as suspicious via WHOIS.
- **Reputation check** — optional integration with Google Safe Browsing and VirusTotal.
- **Risk scoring** — scored 0–100 and categorised as HIGH RISK / MEDIUM RISK / LIKELY SAFE.

---

## Project Structure

```
ScamShield/
├── backend/
│   ├── main.py            # FastAPI app, /analyze endpoint
│   ├── text_check.py      # Gemini LLM scam analysis
│   ├── url_check.py       # Allowlist, WHOIS, Safe Browsing, VirusTotal
│   ├── verdict.py         # Scoring + verdict logic
│   ├── known_domains.json # Trusted domain allowlist
│   └── requirements.txt
├── frontend/
│   └── index.html         # Single-page UI (HTML + CSS + JS)
├── .env.example           # Environment variable template
└── README.md
```

---

## Setup

### 1. Clone / open the project

```bash
cd ScamShield
```

### 2. Create and activate a virtual environment (recommended)

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

### 3. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your keys:

| Variable           | Required | Description                                      |
|--------------------|----------|--------------------------------------------------|
| `GEMINI_API_KEY`   | ✅ Yes   | Google AI Studio key for Gemini text analysis    |
| `SAFE_BROWSING_KEY`| Optional | Google Safe Browsing API key                     |
| `VIRUSTOTAL_KEY`   | Optional | VirusTotal free API key                          |

Get a Gemini key for free at <https://aistudio.google.com/app/apikey>.

### 5. Run the backend server

```bash
uvicorn backend.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

> **Tip:** you can also `cd backend` first and run `uvicorn main:app --reload` — both work.

### 6. Open the frontend

Open `frontend/index.html` directly in your browser (double-click, or `File → Open`).

No build step, no npm, no server needed for the frontend.

---

## API

### `POST /analyze`

**Request body:**
```json
{ "message": "Your MSEDCL power will be cut. Pay now: http://msedcl-pay.site" }
```

**Response:**
```json
{
  "verdict": "HIGH RISK",
  "score": 90,
  "reasons": [
    "Message demands urgent action with a threat",
    "Domain 'msedcl-pay.site' closely resembles known-safe domain 'msedcl.co.in'",
    "Domain registered only 12 day(s) ago"
  ],
  "url_found": "http://msedcl-pay.site",
  "url_status": "suspicious"
}
```

### `GET /health`
Returns `{"status": "ok"}` — useful for uptime checks.

---

## Scoring logic

| Condition                                     | Score |
|-----------------------------------------------|-------|
| Gemini flags text as suspicious               | +40   |
| URL domain is a lookalike or unknown          | +30   |
| URL domain registered < 90 days ago          | +20   |
| URL flagged by Safe Browsing / VirusTotal     | +10   |

| Score   | Verdict      |
|---------|--------------|
| ≥ 70    | HIGH RISK    |
| 35–69   | MEDIUM RISK  |
| < 35    | LIKELY SAFE  |

---

## Notes

- The Safe Browsing and VirusTotal checks are **optional** — if the keys are not set, those checks are silently skipped and the app still works.
- WHOIS lookups can be slow (~2–5 s) for some domains. The overall response time depends on domain WHOIS servers.
- This tool is for **awareness only** and does not constitute legal or financial advice.
