import re
import os
import json
import time
import hashlib
from collections import defaultdict
from typing import Any
import google.generativeai as genai
from dotenv import load_dotenv
from log_parser import parse_log

load_dotenv()

genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")


# ── Regex Patterns ──────────────────────────────────────────────────────────────
PATTERNS = {
    "email":        {"regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",                             "risk": "low"},
    "phone":        {"regex": r"\b(\+?\d[\d\s\-().]{7,}\d)\b",                                                   "risk": "low"},
    "api_key":      {"regex": r"(sk-[a-zA-Z0-9]{20,}|api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9\-_]{16,}['\"]?)", "risk": "high"},
    "password":     {"regex": r"(password|passwd|pwd)\s*[=:]\s*['\"]?(\S+)['\"]?",                               "risk": "critical"},
    "token":        {"regex": r"(token|bearer|auth)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]{20,})['\"]?",               "risk": "high"},
    "secret":       {"regex": r"(secret|private_key|client_secret)\s*[=:]\s*['\"]?(\S+)['\"]?",                 "risk": "critical"},
    "ip_address":   {"regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b","risk": "low"},
    "stack_trace":  {"regex": r"(Exception|Traceback|NullPointerException|at \w+\.\w+\(.*:\d+\))",              "risk": "medium"},
    "credit_card":  {"regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",              "risk": "critical"},
    "jwt":          {"regex": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",               "risk": "high"},
    "aws_key":      {"regex": r"(AKIA|ASIA)[A-Z0-9]{16}",                                                        "risk": "critical"},
    "db_conn":      {"regex": r"(jdbc:|mongodb://|postgresql://|mysql://|redis://)[^\s\"']{10,}",                "risk": "critical"},
}

RISK_SCORES = {"low": 1, "medium": 3, "high": 7, "critical": 10}

# ── Rate Limiter ─────────────────────────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)

def check_rate_limit(client_id: str, max_requests: int = 10, window: int = 60) -> tuple[bool, str]:
    now = time.time()
    timestamps = [t for t in _rate_store[client_id] if now - t < window]
    _rate_store[client_id] = timestamps
    if len(timestamps) >= max_requests:
        wait = int(window - (now - timestamps[0]))
        return False, f"Rate limit exceeded. Try again in {wait}s."
    _rate_store[client_id].append(now)
    return True, "ok"

# ── Chunker for large files ──────────────────────────────────────────────────────
def chunk_content(content: str, chunk_size: int = 3000, overlap: int = 200) -> list[str]:
    """Split large content into overlapping chunks for efficient processing."""
    lines = content.split("\n")
    chunks, current, current_len = [], [], 0
    for line in lines:
        current.append(line)
        current_len += len(line)
        if current_len >= chunk_size:
            chunks.append("\n".join(current))
            # keep last few lines as overlap context
            overlap_lines = []
            overlap_len = 0
            for l in reversed(current):
                if overlap_len + len(l) > overlap:
                    break
                overlap_lines.insert(0, l)
                overlap_len += len(l)
            current = overlap_lines
            current_len = overlap_len
    if current:
        chunks.append("\n".join(current))
    return chunks if chunks else [content]

# ── Regex Detection ──────────────────────────────────────────────────────────────
def run_regex_detection(content: str) -> list[dict]:
    findings = []
    lines = content.split("\n")
    seen = set()  # dedup same type+line
    for ptype, config in PATTERNS.items():
        for line_num, line in enumerate(lines, 1):
            matches = re.findall(config["regex"], line, re.IGNORECASE)
            if matches:
                key = f"{ptype}:{line_num}"
                if key in seen:
                    continue
                seen.add(key)
                value = matches[0] if isinstance(matches[0], str) else matches[0][0]
                findings.append({
                    "type": ptype,
                    "risk": config["risk"],
                    "line": line_num,
                    "value": _mask(value, ptype),
                    "raw_line": line.strip()[:120]
                })
    return findings

def _mask(value: str, ptype: str) -> str:
    if ptype in ("password", "secret", "credit_card", "db_conn", "aws_key"):
        return "***REDACTED***"
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "****"

# ── Risk Engine ──────────────────────────────────────────────────────────────────
def calculate_risk(findings: list[dict]) -> tuple[int, str]:
    if not findings:
        return 0, "none"
    score = min(sum(RISK_SCORES.get(f["risk"], 0) for f in findings), 20)
    level = "critical" if score >= 15 else "high" if score >= 8 else "medium" if score >= 4 else "low"
    return score, level

def apply_policy(risk_level: str, options: dict) -> str:
    if options.get("block_high_risk") and risk_level in ("high", "critical"):
        return "blocked"
    if options.get("mask") and risk_level != "none":
        return "masked"
    return "allowed"

# ── Advanced: Brute Force Detection ─────────────────────────────────────────────
def detect_brute_force(content: str) -> dict | None:
    fail_re = re.compile(r"(failed login|authentication failed|invalid password|login attempt|unauthorized|401)", re.IGNORECASE)
    lines = content.split("\n")
    failed = [i+1 for i, l in enumerate(lines) if fail_re.search(l)]
    if len(failed) >= 3:
        return {"detected": True, "count": len(failed), "lines": failed[:10],
                "risk": "high", "message": f"Possible brute-force: {len(failed)} failed auth attempts"}
    return None

# ── Advanced: Cross-Log Anomaly Detection ────────────────────────────────────────
def detect_anomalies(content: str) -> list[dict]:
    anomalies = []
    lines = content.split("\n")

    # Repeated same error (>= 3 times)
    error_counts: dict[str, list[int]] = defaultdict(list)
    for i, line in enumerate(lines, 1):
        if re.search(r"(ERROR|CRITICAL|FATAL)", line, re.IGNORECASE):
            # normalize: strip timestamps/numbers for grouping
            key = re.sub(r"\d+", "N", line.strip()[:80])
            error_counts[key].append(i)
    for msg, line_nums in error_counts.items():
        if len(line_nums) >= 3:
            anomalies.append({
                "type": "repeated_error",
                "message": f"Same error repeated {len(line_nums)}x",
                "lines": line_nums[:5],
                "risk": "medium"
            })

    # Suspicious IPs making many requests
    ip_lines: dict[str, list[int]] = defaultdict(list)
    ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    for i, line in enumerate(lines, 1):
        for ip in ip_re.findall(line):
            ip_lines[ip].append(i)
    for ip, lns in ip_lines.items():
        if len(lns) >= 5:
            anomalies.append({
                "type": "suspicious_ip",
                "message": f"IP {ip} appears {len(lns)}x across log",
                "lines": lns[:5],
                "risk": "medium"
            })

    # Debug mode in production logs
    if re.search(r"debug\s*=\s*true|DEBUG mode (on|enabled)", content, re.IGNORECASE):
        anomalies.append({"type": "debug_mode", "message": "Debug mode active in logs", "risk": "medium", "lines": []})

    # High error rate (>30% of lines are errors)
    error_lines = sum(1 for l in lines if re.search(r"\b(ERROR|CRITICAL|FATAL)\b", l, re.IGNORECASE))
    if len(lines) > 5 and error_lines / len(lines) > 0.3:
        anomalies.append({
            "type": "high_error_rate",
            "message": f"High error rate: {error_lines}/{len(lines)} lines ({int(error_lines/len(lines)*100)}%)",
            "risk": "high",
            "lines": []
        })

    return anomalies

# ── Advanced: Cross-Entry Correlation ────────────────────────────────────────────
def correlate_entries(content: str) -> list[dict]:
    """Correlate patterns across multiple log entries."""
    correlations = []
    lines = content.split("\n")

    # Find login followed closely by sensitive data access
    for i, line in enumerate(lines):
        if re.search(r"login|authenticated", line, re.IGNORECASE):
            window = lines[i+1:i+6]
            for j, wline in enumerate(window):
                if re.search(r"(admin|root|sudo|DELETE|DROP|TRUNCATE)", wline, re.IGNORECASE):
                    correlations.append({
                        "type": "privilege_escalation_pattern",
                        "message": f"Login at line {i+1} followed by privileged action at line {i+j+2}",
                        "risk": "high"
                    })
                    break

    # Multiple services failing around same time (error clusters)
    error_positions = [i for i, l in enumerate(lines) if re.search(r"ERROR|FATAL", l, re.IGNORECASE)]
    if len(error_positions) >= 3:
        for idx in range(len(error_positions) - 2):
            span = error_positions[idx+2] - error_positions[idx]
            if span <= 5:
                correlations.append({
                    "type": "error_cluster",
                    "message": f"3 errors within {span} lines starting at line {error_positions[idx]+1} — possible cascade failure",
                    "risk": "high"
                })
                break

    return correlations


def _fallback_insights(findings: list[dict], anomalies: list[dict], input_type: str) -> list[str]:
    """Generate meaningful fallback insights from findings when AI call fails."""
    insights = []
    critical = [f for f in findings if f["risk"] == "critical"]
    high     = [f for f in findings if f["risk"] == "high"]
    medium   = [f for f in findings if f["risk"] == "medium"]

    if critical:
        types = list({f["type"] for f in critical})
        lines = [str(f["line"]) for f in critical[:3]]
        insights.append(f"CRITICAL: {', '.join(types)} exposed at line(s) {', '.join(lines)} — rotate immediately")
    if high:
        types = list({f["type"] for f in high})
        lines = [str(f["line"]) for f in high[:3]]
        insights.append(f"HIGH risk: {', '.join(types)} found at line(s) {', '.join(lines)} — investigate and revoke")
    if medium:
        insights.append(f"{len(medium)} medium-risk pattern(s) detected (stack traces, debug info) — review before production")
    if anomalies:
        anom_types = list({a["type"] for a in anomalies})
        insights.append(f"Anomalies detected: {', '.join(anom_types)} — review log patterns for systemic issues")
    if not insights:
        insights.append("No critical issues found — routine security posture looks clean")
    return insights[:3]

# ── Gemini AI Insights ────────────────────────────────────────────────────────────
def get_ai_insights(input_type: str, content: str, findings: list[dict],
                    anomalies: list[dict], correlations: list[dict]) -> tuple[str, list[str]]:
    findings_text = json.dumps(findings[:10], indent=2)
    anomalies_text = json.dumps(anomalies[:5], indent=2)
    corr_text = json.dumps(correlations[:5], indent=2)

    # Use chunking for large content
    chunks = chunk_content(content, chunk_size=3000)
    sample = chunks[0]  # use first chunk for AI context
    chunk_note = f"(showing chunk 1/{len(chunks)})" if len(chunks) > 1 else ""

    prompt = f"""You are a senior security analyst reviewing {input_type} content {chunk_note}.

CONTENT SAMPLE:
{sample}

REGEX FINDINGS:
{findings_text}

ANOMALIES DETECTED:
{anomalies_text}

CORRELATIONS:
{corr_text}

Respond ONLY with valid JSON, no markdown backticks:
{{
  "summary": "specific one-sentence security posture summary referencing actual findings",
  "insights": [
    "actionable insight referencing specific line numbers or patterns found",
    "second insight with concrete remediation step",
    "third insight about systemic risk or pattern"
  ]
}}

Rules: Be specific (mention actual types found, line numbers). Never say 'no issues found' if findings exist. Max 3 insights."""

    try:
        response = model.generate_content(prompt)
        raw = response.text.strip()
        # Strip markdown fences if Gemini wraps in ```json
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
        raw = raw.strip()
        parsed = json.loads(raw)
        return parsed.get("summary", "Analysis complete."), parsed.get("insights", [])
    except json.JSONDecodeError as e:
        # Gemini returned text but not valid JSON — extract what we can
        print(f"[WARN] Gemini JSON parse failed: {e}")
        print(f"[WARN] Raw response: {raw[:300]}")
        # Try to pull summary from raw text
        summary = raw[:200] if raw else f"{len(findings)} security pattern(s) detected in {input_type}"
        return summary, _fallback_insights(findings, anomalies, input_type)
    except Exception as e:
        print(f"[ERROR] Gemini API call failed: {type(e).__name__}: {e}")
        return (
            f"{len(findings)} security pattern(s) detected — {len([f for f in findings if f['risk'] in ('critical','high')])} high/critical issues found in {input_type} content.",
            _fallback_insights(findings, anomalies, input_type)
        )

# ── Main Entry Point ──────────────────────────────────────────────────────────────
async def analyze_content(input_type: str, content: str, options: dict,
                          client_id: str = "default") -> dict[str, Any]:

    # Rate limiting
    allowed, msg = check_rate_limit(client_id)
    if not allowed:
        return {"error": msg, "risk_level": "blocked", "action": "rate_limited"}

    # Chunk info for large files
    chunks = chunk_content(content)
    is_large = len(chunks) > 1

    # Step 1: Regex detection (run on full content)
    findings = run_regex_detection(content)

    # Step 2: Log-specific parsing
    if input_type == "log":
        log_findings = parse_log(content)
        existing = {f["line"] for f in findings}
        for lf in log_findings:
            if lf["line"] not in existing:
                findings.append(lf)

    # Step 3: Advanced analysis
    anomalies = detect_anomalies(content) if input_type == "log" else []
    correlations = correlate_entries(content) if input_type == "log" else []
    brute_force = detect_brute_force(content) if input_type == "log" else None

    # Step 4: Risk scoring
    risk_score, risk_level = calculate_risk(findings)

    # Bump risk if anomalies found
    if any(a["risk"] == "high" for a in anomalies + correlations):
        risk_score = min(risk_score + 3, 20)
        if risk_level == "medium":
            risk_level = "high"

    # Step 5: Gemini AI insights
    summary, insights = get_ai_insights(input_type, content, findings, anomalies, correlations)

    # Step 6: Policy
    action = apply_policy(risk_level, options)

    result: dict[str, Any] = {
        "summary": summary,
        "content_type": input_type,
        "findings": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action,
        "insights": insights,
        "total_findings": len(findings),
        "findings_by_risk": {
            "critical": len([f for f in findings if f["risk"] == "critical"]),
            "high":     len([f for f in findings if f["risk"] == "high"]),
            "medium":   len([f for f in findings if f["risk"] == "medium"]),
            "low":      len([f for f in findings if f["risk"] == "low"]),
        },
        "anomalies": anomalies,
        "correlations": correlations,
        "processing": {
            "chunks_processed": len(chunks),
            "large_file": is_large,
            "total_lines": content.count("\n") + 1
        }
    }

    if brute_force:
        result["brute_force_detected"] = brute_force

    return result
