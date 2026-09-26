# ScamShield

> **Verifies if a message and its link are actually real — not just a spam filter.**

Built for the **IBM Bob 2.0 Hackathon** · Team Doers · MIT License

---

## The Problem

Scam messages in India are engineered to exploit urgency and impersonation. They combine fake sender identities, threatening language, and lookalike URLs to trick people into acting before they think.

Here is a real example that illustrates two classic attack patterns in a single message:

> *"865833 is OTP to Reset the Password for Open Access User: Challan: MH47----, Fine: 3000, Detail: https://mparivahanofficial.com/Xuv. Please do not share with anyone. MSEDCL"*

**Red flag 1 — Mismatched institutions:** MSEDCL is Maharashtra's electricity board. It has zero authority to issue traffic challans. A message combining these two completely unrelated agencies is a textbook social-engineering trick — pile on enough official-sounding details and people stop questioning the logic.

**Red flag 2 — Lookalike domain:** The real vehicle registration portal is `parivahan.gov.in`. The link in the message points to `mparivahanofficial.com` — registered 29 days ago through a Hong Kong registrar, with no SSL certificate, and no hosting in India. ScamShield catches this automatically.

Existing spam filters would likely let this through — the text contains no profanity, no "click here to win", nothing their keyword models are trained on. ScamShield looks at *what the message is claiming*, *who it claims to be from*, and *whether the link is actually trustworthy*.

---

## What ScamShield Does

- **AI text analysis** — Sends the message to Gemini and checks for 8 named fraud patterns independently: urgency/threats, OTP/credential requests, brand impersonation, sender identity mismatch, grammar/tone inconsistencies typical of machine-translated scams, unusual payment channels (gift cards, crypto, UPI to personal accounts), unsolicited prize/loan offers, and "do not share" phrasing.

- **SMS vs Email handling** — Users select the message type before submitting. For SMS, the tool always shows an honest disclosure that SMS sender IDs are trivially spoofed and cannot be verified. For Email, the tool runs live SPF, DKIM, and DMARC DNS checks on the sender's domain and reports pass/fail for each.

- **Domain forensics** — When a URL is found, ScamShield runs five independent checks without requiring any paid API:
  - **Allowlist + lookalike detection:** compares against 30+ known-safe Indian gov/bank domains using string similarity, brand-name embedding, and two-part TLD-aware matching
  - **URL structure analysis:** flags raw IP addresses, URL shorteners, excessive subdomains, and misleading path segments (`/secure-login/`, `/verify-account/`, etc.)
  - **WHOIS registrant info:** extracts domain age, registrar, and registrant org; flags privacy-redacted + very-new domains as a combined pattern
  - **SSL certificate check:** retrieves issuer and issue date; flags certs under 30 days old on unknown domains
  - **Hosting / ASN lookup:** resolves the domain's IP and checks the hosting provider and country; flags non-Indian hosting on domains impersonating Indian institutions

- **Reputation APIs:** optionally calls Google Safe Browsing and VirusTotal if keys are configured — degrades gracefully if not.

- **Investigation-report UI:** results are shown as four collapsible sections — Sender Analysis, Content Analysis, Link Forensics, and Score Breakdown — so the report is scannable at a glance but fully detailed on inspection.

- **Explainable scoring:** every signal that contributes to the risk score is listed with the exact points it added and why, making the verdict transparent rather than a black box.

- **In-memory caching:** identical messages submitted within 1 hour return instantly from cache, marked with a "Cached" indicator.

---

## How It Works

```
User submits message
        │
        ├── Content check (Gemini API)
        │     └─ 8 named scam categories → reasons[]
        │
        ├── Sender check
        │     ├─ SMS → honest spoofing disclaimer (always shown)
        │     └─ Email → SPF / DKIM / DMARC DNS lookups
        │
        └── Link forensics (if URL found)
              ├─ Allowlist + lookalike match
              ├─ URL structure analysis
              ├─ WHOIS registrant + domain age
              ├─ SSL certificate check
              ├─ ASN / hosting country
              └─ Safe Browsing + VirusTotal (optional)

All signals → Verdict engine (verdict.py)
    Score = sum of weighted signals (max 100)
    70+  → HIGH RISK
    35-69 → MEDIUM RISK
    < 35  → LIKELY SAFE
    + score_breakdown[] showing every signal and its points
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend framework | FastAPI + Uvicorn |
| AI text analysis | Google Gemini 2.0 Flash (`google-genai`) |
| DNS lookups (SPF/DMARC/DKIM) | `dnspython` |
| WHOIS domain info | `python-whois` |
| SSL certificate check | Python built-in `ssl` + `socket` |
| ASN / hosting lookup | `ipwhois` |
| HTTP requests (reputation APIs) | `requests` |
| Environment config | `python-dotenv` |
| Data validation | `pydantic` |
| URL reputation | Google Safe Browsing API (optional) |
| URL reputation | VirusTotal API v3 (optional) |
| Frontend | Plain HTML + CSS + vanilla JS (no framework) |

---

## Setup & Running

### 1. Clone the repo

```bash
git clone <repo-url>
cd ScamShield
```

### 2. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 3. Configure API keys

```bash
# From the project root:
cp .env.example backend/.env
```

Open `backend/.env` and fill in your keys:

| Variable | Required | Where to get it |
|---|---|---|
| `GEMINI_API_KEY` | ✅ Yes | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) — free |
| `SAFE_BROWSING_KEY` | Optional | Google Cloud Console → Safe Browsing API |
| `VIRUSTOTAL_KEY` | Optional | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) — free tier |

The app works without the optional keys — those checks are silently skipped.

### 4. Start the backend

```bash
# From inside the backend/ directory:
uvicorn main:app --reload
```

Server starts at `http://127.0.0.1:8000`. The `--reload` flag restarts automatically on code changes.

### 5. Open the frontend

Open `frontend/index.html` directly in your browser — double-click it in Explorer, or use `File → Open` in your browser. No build step, no npm.

---

## Screenshots

![Screenshot](screenshot.png)

---

## API Reference

### `POST /analyze`

```json
{
  "message": "Your MSEDCL bill is overdue. Pay now: http://msedcl-pay.site",
  "message_type": "sms",
  "sender_email": null
}
```

**Response:**
```json
{
  "verdict": "HIGH RISK",
  "score": 85,
  "score_breakdown": [
    { "signal": "AI text analysis", "points": 40, "detail": "Flagged: Urgency / threats, Brand/agency impersonation" },
    { "signal": "Domain lookalike",  "points": 25, "detail": "Domain 'msedcl-pay.site' closely resembles 'msedcl.co.in'" },
    { "signal": "Domain age",        "points": 20, "detail": "Domain registered only 12 day(s) ago" }
  ],
  "reasons": [ "..." ],
  "url_found": "http://msedcl-pay.site",
  "url_status": "suspicious",
  "sender_analysis": { "type": "sms", "disclaimer": "..." },
  "email_auth": null,
  "domain_forensics": { "whois_info": {}, "ssl_info": {}, "hosting_info": {}, ... },
  "cached": false
}
```

### `GET /health`

Returns `{ "status": "ok", "cache_entries": <n> }`.

---

## Limitations

- **SMS sender identity is unverifiable** — the Sender ID field in SMS is trivially spoofable by anyone with a bulk SMS gateway. ScamShield discloses this honestly rather than pretending to verify it.
- **Rate limits apply** — the Gemini free tier, Safe Browsing API, and VirusTotal free tier all have request quotas. Heavy use will hit limits.
- **WHOIS privacy redaction** — many registrars redact registrant details by default. ScamShield surfaces this as-is and flags the combination of privacy redaction + very new domain as suspicious, but cannot pierce the redaction.
- **Not a replacement for official reporting** — if you receive a scam message, report it to [cybercrime.gov.in](https://cybercrime.gov.in) or call 1930 (India's cyber fraud helpline).

---

## Roadmap

- **Browser extension** — highlight suspicious links inline on any webpage
- **WhatsApp Business API integration** — verify messages forwarded directly to a ScamShield bot
- **Fine-tuned model on IBM Granite** — replace the general-purpose Gemini prompt with a domain-specific model trained on annotated Indian scam corpora
- **Enterprise API for telecoms and banks** — integrate into SMS delivery pipelines to flag messages before they reach customers

---

## Team

Built by **Team Doers** for the IBM Bob 2.0 Hackathon.

---

## License

MIT License — see [LICENSE](LICENSE) for full text.
