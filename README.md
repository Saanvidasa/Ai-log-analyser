# AI Secure Data Intelligence Platform

FastAPI + Gemini AI security scanner with real-time log streaming.

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env        # add your Gemini key
uvicorn main:app --reload   # visit http://localhost:8000
```

## Get Free Gemini API Key
Go to https://aistudio.google.com → "Get API Key" → copy → paste in .env

## Features
- Multi-input: text, log, SQL, chat, file upload
- 12 regex pattern types (passwords, API keys, JWTs, AWS keys, DB strings...)
- Log analyzer: line-by-line parsing with risk classification
- Anomaly detection: repeated errors, high error rate, suspicious IPs, debug mode
- Cross-entry correlation: privilege escalation patterns, error clusters
- Brute force detection
- Real-time streaming via SSE (⚡ mode)
- Efficient chunking for large files
- Rate limiting (10 req/min per IP)
- Gemini AI insights (specific, actionable)
- Risk engine: 0-20 score → critical/high/medium/low
- Policy engine: mask or block

## API Endpoints
- POST /analyze       — JSON body analysis
- POST /analyze/upload — file upload
- POST /analyze/stream — real-time SSE streaming (log only)
- GET  /health
