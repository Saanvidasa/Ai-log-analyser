from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional, AsyncGenerator
import uvicorn
import json
import asyncio

from analyzer import (
    analyze_content,
    chunk_content,
    run_regex_detection,
    detect_anomalies,
    correlate_entries,
    detect_brute_force,
    calculate_risk,
)
from log_parser import parse_log

app = FastAPI(title="AI Secure Data Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

VALID_INPUT_TYPES = {"text", "file", "sql", "chat", "log"}


class AnalyzeRequest(BaseModel):
    input_type: str
    content: str
    options: Optional[dict] = None


@app.get("/")
def root():
    return FileResponse("static/index.html")


@app.post("/analyze")
async def analyze(request: Request, body: AnalyzeRequest):
    if not body.content.strip():
        raise HTTPException(400, "Content cannot be empty")
    if body.input_type not in VALID_INPUT_TYPES:
        raise HTTPException(
            400, f"Invalid input_type. Must be one of: {', '.join(VALID_INPUT_TYPES)}"
        )

    client_id = request.client.host if request.client else "default"
    result = await analyze_content(
        input_type=body.input_type,
        content=body.content,
        options=body.options or {"mask": True, "block_high_risk": False},
        client_id=client_id,
    )
    if "error" in result:
        raise HTTPException(429, result["error"])
    return result


@app.post("/analyze/upload")
async def analyze_upload(request: Request, file: UploadFile = File(...)):
    content_bytes = await file.read()

    if len(content_bytes) > 5 * 1024 * 1024:
        raise HTTPException(413, "File too large. Maximum size is 5MB.")

    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be text-based (.log, .txt, .sql)")

    if not text.strip():
        raise HTTPException(400, "Uploaded file is empty")

    filename = file.filename or ""
    if filename.endswith(".sql"):
        input_type = "sql"
    elif filename.endswith(".log"):
        input_type = "log"
    else:
        # Broad sniff — check first 1000 chars for any log-like signal
        import re as _re
        sample = text[:1000].upper()
        log_keywords = ("ERROR", "INFO", "DEBUG", "WARN", "FATAL", "TRACE",
                        "CRITICAL", "EXCEPTION", "FAILED LOGIN",
                        "AUTHENTICATION", "UNAUTHORIZED",
                        "NULLPOINTEREXCEPTION", "TRACEBACK")
        has_timestamp = bool(
            _re.search(r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}", text[:1000])
            or _re.search(r"\[\d{2}:\d{2}:\d{2}\]", text[:1000])
        )
        input_type = (
            "log"
            if any(k in sample for k in log_keywords) or has_timestamp
            else "text"
        )

    client_id = request.client.host if request.client else "default"
    result = await analyze_content(
        input_type=input_type,
        content=text,
        options={"mask": True, "block_high_risk": False},
        client_id=client_id,
    )
    if "error" in result:
        raise HTTPException(429, result["error"])
    return result


# ── Real-time streaming endpoint ──────────────────────────────────────────────
async def stream_log_analysis(content: str) -> AsyncGenerator[str, None]:
    """Stream log analysis chunk by chunk using SSE format."""
    chunks = chunk_content(content, chunk_size=2000)
    total = len(chunks)

    yield f"data: {json.dumps({'event': 'start', 'total_chunks': total, 'total_lines': content.count(chr(10)) + 1})}\n\n"
    await asyncio.sleep(0.05)

    all_findings: list[dict] = []
    all_anomalies: list[dict] = []
    # Global dedup set across ALL chunks: "type:line"
    seen_keys: set[str] = set()

    for i, chunk in enumerate(chunks):
        chunk_findings = run_regex_detection(chunk)
        chunk_log = parse_log(chunk)
        chunk_anomalies = detect_anomalies(chunk)

        # Collect only NEW findings not yet seen across prior chunks
        new_this_chunk: list[dict] = []
        for f in chunk_findings + chunk_log:
            key = f"{f['type']}:{f['line']}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_findings.append(f)
                new_this_chunk.append(f)  # track what's genuinely new this chunk

        all_anomalies.extend(chunk_anomalies)

        progress = round((i + 1) / total * 100)

        yield f"data: {json.dumps({'event': 'chunk', 'chunk': i + 1, 'total': total, 'progress': progress, 'findings_so_far': len(all_findings), 'chunk_findings': new_this_chunk[:5]})}\n\n"
        await asyncio.sleep(0.1)

    # Final risk score over all findings
    correlations = correlate_entries(content)
    brute_force = detect_brute_force(content)
    anomaly_bonus = (
        3 if any(a["risk"] == "high" for a in all_anomalies + correlations) else 0
    )
    risk_score, risk_level = calculate_risk(all_findings, extra=anomaly_bonus)

    complete_payload: dict = {
        "event": "complete",
        "total_findings": len(all_findings),
        "total_anomalies": len(all_anomalies),
        "findings": all_findings[:50],
        "anomalies": all_anomalies,
        "correlations": correlations,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings_by_risk": {
            "critical": len([f for f in all_findings if f["risk"] == "critical"]),
            "high": len([f for f in all_findings if f["risk"] == "high"]),
            "medium": len([f for f in all_findings if f["risk"] == "medium"]),
            "low": len([f for f in all_findings if f["risk"] == "low"]),
        },
    }
    if brute_force:
        complete_payload["brute_force_detected"] = brute_force

    yield f"data: {json.dumps(complete_payload)}\n\n"


@app.post("/analyze/stream")
async def analyze_stream(body: AnalyzeRequest):
    """Real-time streaming log analysis via Server-Sent Events."""
    if not body.content.strip():
        raise HTTPException(400, "Content cannot be empty")
    if body.input_type != "log":
        raise HTTPException(400, "Streaming is only available for log input type")
    return StreamingResponse(
        stream_log_analysis(body.content),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/health")
def health():
    return {"status": "ok", "ai": "gemini-2.5-flash-preview-04-17"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)