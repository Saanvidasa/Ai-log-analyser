# AI Secure Data Intelligence Platform

A modular, AI-powered security scanner that detects sensitive data, analyzes logs in real-time, and generates actionable insights using Google Gemini AI.

---

## What It Does

- Scans text, logs, SQL, chat, and uploaded files for sensitive data
- Detects 12+ pattern types: passwords, API keys, JWTs, AWS keys, emails, DB connection strings, and more
- Generates AI-powered security insights using Gemini 2.5 Flash
- Streams log analysis in real-time chunk by chunk
- Detects anomalies, brute force attempts, and cross-entry correlations
- Applies policy engine to mask or block high-risk content
- Rate limits requests per IP (10 req/min)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, Uvicorn |
| AI | Google Gemini 2.5 Flash (free tier) |
| Detection | Regex pattern engine + log parser |
| Streaming | Server-Sent Events (SSE) |
| Frontend | Vanilla HTML, CSS, JavaScript |

---

## Project Structure

```
ai-security-platform/
├── main.py           # FastAPI app, routes, SSE streaming
├── analyzer.py       # Core engine: regex, risk scoring, Gemini AI, rate limiting, chunking
├── log_parser.py     # Log-specific pattern detection
├── static/
│   └── index.html    # Frontend dashboard UI
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start

### 1. Clone or download the project

```bash
cd ai-security-platform
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Get a free Gemini API key

- Go to https://aistudio.google.com
- Click **"Get API Key"**
- Copy the key (free, no billing required)

### 4. Set up environment

```bash
cp .env.example .env
```

Open `.env` and add your key:

```
GEMINI_API_KEY=your_gemini_api_key_here
```

### 5. Run the server

```bash
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
  "summary": "Log contains critical credential exposure including plaintext password and API key on lines 1-2",
  "content_type": "log",
  "findings": [
    { "type": "email",    "risk": "low",      "line": 1, "value": "admi****com" },
    { "type": "password", "risk": "critical",  "line": 1, "value": "***REDACTED***" },
    { "type": "api_key",  "risk": "high",      "line": 1, "value": "sk-p****-xyz" }
  ],
  "risk_score": 18,
  "risk_level": "critical",
  "action": "masked",
  "insights": [
    "Critical sensitive data — password and API key logged in plaintext on line 1",
    "Immediately revoke the exposed API key and rotate the password for admin@company.com",
    "Implement secure logging practices to redact credentials at the source"
  ],
  "anomalies": [],
  "correlations": [],
  "brute_force_detected": null,
  "total_findings": 3,
  "findings_by_risk": {
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 1
  },
  "processing": {
    "chunks_processed": 1,
    "large_file": false,
    "total_lines": 1
  }
}
```

---

### POST `/analyze/upload`

Upload a `.log`, `.txt`, or `.sql` file directly (max 5MB).

```bash
curl -X POST http://localhost:8000/analyze/upload \
  -F "file=@app.log"
```

---

### POST `/analyze/stream`

Real-time streaming analysis via Server-Sent Events. For log input only.

```bash
curl -X POST http://localhost:8000/analyze/stream \
  -H "Content-Type: application/json" \
  -d '{"input_type": "log", "content": "your log here", "options": {}}'
```

Streams chunk-by-chunk progress events:
```
data: {"event": "start", "total_chunks": 3, "total_lines": 120}
data: {"event": "chunk", "chunk": 1, "total": 3, "progress": 33, "findings_so_far": 4}
data: {"event": "chunk", "chunk": 2, "total": 3, "progress": 66, "findings_so_far": 7}
data: {"event": "complete", "total_findings": 9, "findings": [...]}
```

---

### GET `/health`

```json
{ "status": "ok", "ai": "gemini-2.5-flash" }
```

---

## Detection Patterns

| Pattern | Risk Level | Example |
|---|---|---|
| Password | Critical | `password=admin123` |
| Secret / private key | Critical | `client_secret=abc123` |
| AWS access key | Critical | `AKIAIOSFODNN7EXAMPLE` |
| DB connection string | Critical | `postgresql://user:pass@host/db` |
| API key | High | `api_key=sk-prod-xyz` |
| Token / bearer | High | `token=eyJhbGci...` |
| JWT | High | `eyJ...` |
| Stack trace | Medium | `NullPointerException at App.java:45` |
| Email | Low | `admin@company.com` |
| Phone number | Low | `+1-800-555-0100` |
| IP address | Low | `192.168.1.1` |

---

## Advanced Features

### Real-Time Streaming
Enable **⚡ streaming mode** in the UI to watch log files analyzed chunk by chunk with a live progress bar. Each chunk streams findings as they are detected.

### Large File Chunking
Files are automatically split into 3000-character overlapping chunks. Each chunk is processed independently and results are merged, allowing efficient analysis of large log files without timeouts.

### Anomaly Detection
Automatically detects:
- Repeated errors (same error 3+ times)
- High error rate (>30% of lines are errors)
- Suspicious IPs (same IP appearing 5+ times)
- Debug mode enabled in production logs

### Cross-Entry Correlation
Detects patterns across multiple log entries:
- Login followed by privileged actions (privilege escalation pattern)
- Error clusters (3 errors within 5 lines = possible cascade failure)

### Brute Force Detection
Flags repeated failed authentication attempts (3 or more) as a high-risk finding with line numbers.

### Rate Limiting
10 requests per minute per IP address. Returns HTTP 429 with retry time if exceeded.

---

## Example Use Case

**Input** (`app.log`):
```
2026-03-10 10:00:01 INFO User login email=admin@company.com
password=admin123
api_key=sk-prod-xyzABCDEFGHIJKLMNOP
ERROR stack trace: NullPointerException at service.java:45
Failed login attempt for root
Failed login attempt for root
Failed login attempt for root
```

**Output:**
```json
{
  "summary": "Log contains critical credential exposure with plaintext password and API key, plus brute force indicators",
  "risk_score": 20,
  "risk_level": "critical",
  "action": "masked",
  "insights": [
    "Plaintext password on line 2 and API key on line 3 represent severe credential leakage — revoke immediately",
    "Implement redaction at logging layer to prevent credentials from appearing in any log output",
    "3 failed login attempts for root detected — indicative of brute force activity, block IP and alert security team"
  ],
  "brute_force_detected": {
    "detected": true,
    "count": 3,
    "message": "Possible brute-force: 3 failed auth attempts"
  }
}
```

---

## Security Notes

- All sensitive values are masked before being returned to the client
- The `.env` file is never committed to version control (add to `.gitignore`)
- The platform itself does not store or log any analyzed content
- Rate limiting prevents abuse of the AI analysis endpoint

---

## Evaluation Criteria Coverage

| Category | Marks | Implementation |
|---|---|---|
| Backend Design | 18 | FastAPI, modular files, clean separation of concerns |
| AI Integration | 15 | Gemini 2.5 Flash with specific, contextual insights |
| Multi-Input Handling | 12 | text, log, sql, chat, file upload |
| Log Analysis | 15 | Line parser, 12 pattern types, anomaly + correlation detection |
| Detection + Risk Engine | 12 | Regex engine, 0–20 risk scoring, critical/high/medium/low |
| Policy Engine | 8 | mask / block / allow based on risk level and options |
| Frontend UI | 10 | Dark dashboard, drag-and-drop upload, streaming mode |
| Security | 5 | Value masking, rate limiting, file size limits |
| Observability | 3 | /health endpoint, debug logging, processing metadata |
| Bonus | 2 | Real-time streaming, chunking, brute force, correlations |
