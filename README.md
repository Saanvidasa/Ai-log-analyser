# AI Secure Data Intelligence Platform

A modular, AI-powered security scanner that detects sensitive data, analyzes logs in real-time, and generates actionable insights using Google Gemini AI.

---
##Deployed Linl
https://ai-log-analyser-smv6.onrender.com/

## What It Does

* Scans text, logs, SQL, chat, and uploaded files for sensitive data
* Detects 12+ pattern types: passwords, API keys, JWTs, AWS keys, emails, DB connection strings, and more
* Generates AI-powered security insights using Gemini 2.5 Flash
* Streams log analysis in real-time chunk by chunk
* Detects anomalies, brute force attempts, and cross-entry correlations
* Applies policy engine to mask or block high-risk content
* Rate limits requests per IP (10 req/min)

---

## Tech Stack

| Layer     | Technology                          |
| --------- | ----------------------------------- |
| Backend   | Python, FastAPI, Uvicorn            |
| AI        | Google Gemini 2.5 Flash (free tier) |
| Detection | Regex pattern engine + log parser   |
| Streaming | Server-Sent Events (SSE)            |
| Frontend  | Vanilla HTML, CSS, JavaScript       |

---

## Project Structure

```
ai-security-platform/
├── main.py
├── analyzer.py
├── log_parser.py
├── static/
│   └── index.html
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start

### 1. Clone or download the project

```
cd ai-security-platform
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Get a free Gemini API key

* Go to https://aistudio.google.com
* Click **"Get API Key"**
* Copy the key

### 4. Set up environment

```
cp .env.example .env
```

Add your key:

```
GEMINI_API_KEY=your_gemini_api_key_here
```

### 5. Run the server

```
uvicorn main:app --reload
```

### 6. Open the dashboard

Visit http://localhost:8000

---

## API Reference

### POST `/analyze`

Analyze text, log, SQL, or chat content.

**Request:**

```json
{
  "input_type": "log",
  "content": "2026-03-10 INFO email=admin@company.com password=admin123 api_key=sk-prod-xyz",
  "options": {
    "mask": true,
    "block_high_risk": false,
    "log_analysis": true
  }
}
```

**Response:**

```json
{
  "summary": "Log contains critical credential exposure including plaintext password and API key",
  "content_type": "log",
  "risk_score": 18,
  "risk_level": "critical",
  "action": "masked"
}
```

---

### POST `/analyze/upload`

Upload a `.log`, `.txt`, or `.sql` file (max 5MB).

---

### POST `/analyze/stream`

Real-time streaming analysis via SSE (log input only).

---

### GET `/health`

```json
{ "status": "ok", "ai": "gemini-2.5-flash" }
```

---

## Detection Patterns

| Pattern              | Risk Level | Example                               |
| -------------------- | ---------- | ------------------------------------- |
| Password             | Critical   | `password=admin123`                   |
| Secret / private key | Critical   | `client_secret=abc123`                |
| AWS access key       | Critical   | `AKIAIOSFODNN7EXAMPLE`                |
| DB connection string | Critical   | `postgresql://user:pass@host/db`      |
| API key              | High       | `api_key=sk-prod-xyz`                 |
| Token / bearer       | High       | `token=eyJhbGci...`                   |
| JWT                  | High       | `eyJ...`                              |
| Stack trace          | Medium     | `NullPointerException at App.java:45` |
| Email                | Low        | `admin@company.com`                   |
| Phone number         | Low        | `+1-800-555-0100`                     |
| IP address           | Low        | `192.168.1.1`                         |

---

## Advanced Features

* Real-time streaming (SSE)
* Large file chunking
* Anomaly detection (errors, IP patterns, debug mode)
* Cross-entry correlation
* Brute force detection
* Rate limiting (10 req/min per IP)

---

## Security Notes

* Sensitive values are masked before returning
* `.env` is excluded using `.gitignore`
* No analyzed data is stored
* Rate limiting prevents abuse

---

## Evaluation Criteria Coverage

| Category       | Implementation                   |
| -------------- | -------------------------------- |
| Backend Design | FastAPI, modular structure       |
| AI Integration | Gemini insights                  |
| Multi-Input    | text, log, SQL, chat, upload     |
| Log Analysis   | pattern + anomaly detection      |
| Risk Engine    | scoring + classification         |
| Policy Engine  | mask / block                     |
| Frontend       | dashboard UI                     |
| Security       | masking + rate limiting          |
| Observability  | `/health` endpoint               |
| Bonus          | streaming, chunking, brute force |
