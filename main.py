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

from analyzer import analyze_content, chunk_content, run_regex_detection, parse_log, detect_anomalies

app = FastAPI(title="AI Secure Data Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

class AnalyzeRequest(BaseModel):
    input_type: str
    content: str
    options: Optional[dict] = {"mask": True, "block_high_risk": False, "log_analysis": True}

@app.get("/")
def root():
    return FileResponse("static/index.html")

@app.post("/analyze")
async def analyze(request: Request, body: AnalyzeRequest):
    if not body.content.strip():
        raise HTTPException(400, "Content cannot be empty")
    if body.input_type not in ["text", "file", "sql", "chat", "log"]:
        raise HTTPException(400, "Invalid input_type")
    client_id = request.client.host if request.client else "default"
    result = await analyze_content(
        input_type=body.input_type,
        content=body.content,
        options=body.options or {},
        client_id=client_id
    )
    if "error" in result:
        raise HTTPException(429, result["error"])
    return result

@app.post("/analyze/upload")
async def analyze_upload(request: Request, file: UploadFile = File(...)):
    content_bytes = await file.read()

    # File size limit: 5MB
    if len(content_bytes) > 5 * 1024 * 1024:
        raise HTTPException(413, "File too large. Maximum size is 5MB.")

    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be text-based (.log, .txt, .sql)")

    filename = file.filename or ""
    if filename.endswith(".sql"):
        input_type = "sql"
    elif filename.endswith(".log"):
        input_type = "log"
    else:
        input_type = "log" if any(k in text[:500] for k in ["ERROR", "INFO", "DEBUG", "WARN"]) else "text"

    client_id = request.client.host if request.client else "default"
    result = await analyze_content(
        input_type=input_type,
        content=text,
        options={"mask": True, "block_high_risk": False, "log_analysis": True},
        client_id=client_id
    )
    if "error" in result:
        raise HTTPException(429, result["error"])
    return result

# ── Real-time streaming endpoint ──────────────────────────────────────────────
async def stream_log_analysis(content: str) -> AsyncGenerator[str, None]:
    """Stream log analysis chunk by chunk using SSE format."""
    chunks = chunk_content(content, chunk_size=2000)
    total = len(chunks)

    yield f"data: {json.dumps({'event': 'start', 'total_chunks': total, 'total_lines': content.count(chr(10))+1})}\n\n"
    await asyncio.sleep(0.05)

    all_findings = []
    all_anomalies = []

    for i, chunk in enumerate(chunks):
        # Per-chunk regex
        chunk_findings = run_regex_detection(chunk)
        chunk_log = parse_log(chunk)
        chunk_anomalies = detect_anomalies(chunk)

        all_findings.extend(chunk_findings)
        all_findings.extend(chunk_log)
        all_anomalies.extend(chunk_anomalies)

        progress = round((i + 1) / total * 100)
        yield f"data: {json.dumps({'event': 'chunk', 'chunk': i+1, 'total': total, 'progress': progress, 'findings_so_far': len(all_findings), 'chunk_findings': chunk_findings[:5]})}\n\n"
        await asyncio.sleep(0.1)

    yield f"data: {json.dumps({'event': 'complete', 'total_findings': len(all_findings), 'total_anomalies': len(all_anomalies), 'findings': all_findings[:50], 'anomalies': all_anomalies})}\n\n"

@app.post("/analyze/stream")
async def analyze_stream(body: AnalyzeRequest):
    """Real-time streaming log analysis via Server-Sent Events."""
    if body.input_type != "log":
        raise HTTPException(400, "Streaming is only available for log input type")
    return StreamingResponse(
        stream_log_analysis(body.content),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

@app.get("/health")
def health():
    return {"status": "ok", "ai": "gemini-1.5-flash"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
