import re
import os
import json
import time
import asyncio
import hashlib
from collections import defaultdict
from typing import Any
from google import genai
from google.genai import types
from dotenv import load_dotenv
from log_parser import parse_log

load_dotenv()

_api_key = os.environ.get("GEMINI_API_KEY", "").strip()
if not _api_key:
    raise EnvironmentError(
        "GEMINI_API_KEY is not set. "
        "Create a .env file in the project root with: GEMINI_API_KEY=your_key_here"
    )

client = genai.Client(api_key=_api_key)

# ── Regex Patterns ──────────────────────────────────────────────────────────────
# IMPORTANT: Order matters for display, but detection is independent.
# Phone regex is intentionally strict to avoid matching IP addresses / version strings.
PATTERNS = {
    # Emails — low risk
    "email": {
        "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "risk": "low",
    },
    # Phone — strict: requires space/dash/dot separator OR parentheses so bare
    # dotted quads (IPs) and semver strings are NOT matched.
    # Valid:  +91 98765 43210 | (800) 555-1234 | 800-555-1234
    # Invalid: 192.168.1.1 | 1.2.3 | sk-1234567890
    "phone": {
        "regex": (
            r"\b("
            r"\+?1?\s*\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}"   # US/CA: (800) 555-1234
            r"|"
            r"\+?\d{1,3}[\s\-]\d{2,5}[\s\-]\d{4,10}"          # Intl with separators: +91 98765-43210
            r")\b"
        ),
        "risk": "low",
    },
    # API keys — high risk
    "api_key": {
        "regex": (
            r"(sk-[a-zA-Z0-9]{20,}"
            r"|api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9\-_]{16,}['\"]?)"
        ),
        "risk": "high",
    },
    # Passwords — critical
    "password": {
        "regex": r"(password|passwd|pwd)\s*[=:]\s*['\"]?(\S+)['\"]?",
        "risk": "critical",
    },
    # Tokens — high risk
    "token": {
        "regex": r"(token|bearer|auth)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]{20,})['\"]?",
        "risk": "high",
    },
    # Secrets — critical
    "secret": {
        "regex": r"(secret|private_key|client_secret)\s*[=:]\s*['\"]?(\S+)['\"]?",
        "risk": "critical",
    },
    # IP addresses — strict dotted-quad only (each octet 0-255), low risk.
    # This runs BEFORE phone so IPs are claimed first.
    "ip_address": {
        "regex": (
            r"\b"
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"\b"
        ),
        "risk": "low",
    },
    # Stack traces — medium risk
    "stack_trace": {
        "regex": r"(Exception|Traceback|NullPointerException|at \w+\.\w+\(.*:\d+\))",
        "risk": "medium",
    },
    # Credit cards — critical
    "credit_card": {
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "risk": "critical",
    },
    # JWTs — high risk
    "jwt": {
        "regex": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "risk": "high",
    },
    # AWS access key IDs — critical
    "aws_key": {
        "regex": r"\b(AKIA|ASIA)[A-Z0-9]{16}\b",
        "risk": "critical",
    },
    # Database connection strings — critical
    "db_conn": {
        "regex": r"(jdbc:|mongodb://|postgresql://|mysql://|redis://)[^\s\"']{10,}",
        "risk": "critical",
    },
}

RISK_SCORES = {"low": 1, "medium": 3, "high": 7, "critical": 10}

# ── Rate Limiter ─────────────────────────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_store_last_cleanup: float = time.time()


def _cleanup_rate_store(window: int = 60) -> None:
    """Evict stale client entries to prevent memory leak."""
    global _rate_store_last_cleanup
    now = time.time()
    if now - _rate_store_last_cleanup < window:
        return
    stale = [
        cid for cid, ts in _rate_store.items()
        if not any(now - t < window for t in ts)
    ]
    for cid in stale:
        del _rate_store[cid]
    _rate_store_last_cleanup = now


def check_rate_limit(
    client_id: str, max_requests: int = 10, window: int = 60
) -> tuple[bool, str]:
    _cleanup_rate_store(window)
    now = time.time()
    timestamps = [t for t in _rate_store[client_id] if now - t < window]
    _rate_store[client_id] = timestamps
    if len(timestamps) >= max_requests:
        wait = int(window - (now - timestamps[0]))
        return False, f"Rate limit exceeded. Try again in {wait}s."
    _rate_store[client_id].append(now)
    return True, "ok"


# ── Chunker for large files ──────────────────────────────────────────────────────
def chunk_content(
    content: str, chunk_size: int = 3000, overlap: int = 200
) -> list[str]:
    """Split large content into overlapping chunks for efficient processing."""
    lines = content.split("\n")
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for line in lines:
        current.append(line)
        current_len += len(line) + 1  # +1 for the newline

        if current_len >= chunk_size:
            chunks.append("\n".join(current))

            # Build overlap: keep last N characters worth of lines
            overlap_lines: list[str] = []
            overlap_len = 0
            for l in reversed(current):
                if overlap_len + len(l) + 1 > overlap:
                    break
                overlap_lines.insert(0, l)
                overlap_len += len(l) + 1

            # Reset current to overlap lines only
            current = overlap_lines
            current_len = overlap_len

    if current:
        chunks.append("\n".join(current))

    return chunks if chunks else [content]


# ── Regex Detection ──────────────────────────────────────────────────────────────
def run_regex_detection(content: str) -> list[dict]:
    """
    Run all PATTERNS against content.

    IP-address lines are claimed first so the (looser) phone pattern cannot
    re-match them.  We track claimed lines per-type to avoid double-counting.
    """
    findings: list[dict] = []
    lines = content.split("\n")

    # Track which line_numbers have already been claimed by ip_address so the
    # phone pattern skips those lines entirely.
    ip_claimed_lines: set[int] = set()

    # Run ip_address first, then everything else
    ordered_types = ["ip_address"] + [k for k in PATTERNS if k != "ip_address"]

    # Dedup by (type, line_number)
    seen: set[str] = set()

    for ptype in ordered_types:
        config = PATTERNS[ptype]
        for line_num, line in enumerate(lines, 1):
            # Skip phone detection on lines that contain an IP address
            if ptype == "phone" and line_num in ip_claimed_lines:
                continue

            matches = re.findall(config["regex"], line, re.IGNORECASE)
            if not matches:
                continue

            key = f"{ptype}:{line_num}"
            if key in seen:
                continue
            seen.add(key)

            raw_match = matches[0]
            value = raw_match if isinstance(raw_match, str) else raw_match[0]

            if ptype == "ip_address":
                ip_claimed_lines.add(line_num)

            findings.append(
                {
                    "type": ptype,
                    "risk": config["risk"],
                    "line": line_num,
                    "value": _mask(value, ptype),
                    "raw_line": line.strip()[:120],
                }
            )

    return findings


def _mask(value: str, ptype: str) -> str:
    if ptype in ("password", "secret", "credit_card", "db_conn", "aws_key"):
        return "***REDACTED***"
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "****"


# ── Risk Engine ──────────────────────────────────────────────────────────────────
def calculate_risk(findings: list[dict], extra: int = 0) -> tuple[int, str]:
    if not findings and extra == 0:
        return 0, "none"
    raw = sum(RISK_SCORES.get(f["risk"], 0) for f in findings) + extra
    score = min(raw, 20)
    level = (
        "critical" if score >= 15
        else "high" if score >= 8
        else "medium" if score >= 4
        else "low"
    )
    return score, level


def apply_policy(risk_level: str, options: dict) -> str:
    if options.get("block_high_risk") and risk_level in ("high", "critical"):
        return "blocked"
    if options.get("mask") and risk_level != "none":
        return "masked"
    return "allowed"


# ── Advanced: Brute Force Detection ─────────────────────────────────────────────
def detect_brute_force(content: str) -> dict | None:
    """
    Detects brute-force patterns: 3+ auth failures anywhere in the log,
    OR 2+ failures within a tight 10-line window (rapid burst).
    """
    fail_re = re.compile(
        r"(failed login|authentication failed|invalid password|invalid credentials?"
        r"|login attempt|unauthorized|access denied|401|403)",
        re.IGNORECASE,
    )
    lines = content.split("\n")
    failed = [i + 1 for i, l in enumerate(lines) if fail_re.search(l)]

    if not failed:
        return None

    # Rapid burst: 2+ failures within any 10-line window
    rapid = False
    for idx in range(len(failed) - 1):
        if failed[idx + 1] - failed[idx] <= 10:
            rapid = True
            break

    if len(failed) >= 3 or (len(failed) >= 2 and rapid):
        return {
            "detected": True,
            "count": len(failed),
            "lines": failed[:10],
            "risk": "high",
            "message": (
                f"Possible brute-force: {len(failed)} failed auth attempt(s)"
                + (" in rapid succession" if rapid else "")
            ),
        }
    return None


# ── Advanced: Cross-Log Anomaly Detection ────────────────────────────────────────
def detect_anomalies(content: str) -> list[dict]:
    anomalies: list[dict] = []
    lines = content.split("\n")
    non_empty = [l for l in lines if l.strip()]

    # ── 1. Repeated similar errors (threshold: 2+, not 3+) ───────────────────
    # Normalize digits AND timestamps so "same error at different times" clusters.
    error_counts: dict[str, list[int]] = defaultdict(list)
    ts_re = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\d]*")
    for i, line in enumerate(lines, 1):
        if re.search(r"(ERROR|CRITICAL|FATAL)", line, re.IGNORECASE):
            # strip timestamp, then normalize remaining digits
            stripped = ts_re.sub("", line.strip())
            key = re.sub(r"\d+", "N", stripped)[:80]
            error_counts[key].append(i)
    for msg, line_nums in error_counts.items():
        if len(line_nums) >= 2:  # lowered from 3 → 2
            anomalies.append(
                {
                    "type": "repeated_error",
                    "message": f"Same error pattern repeated {len(line_nums)}x",
                    "lines": line_nums[:5],
                    "risk": "medium",
                }
            )

    # ── 2. Suspicious IPs (threshold: 3+, not 5+) ────────────────────────────
    ip_lines: dict[str, list[int]] = defaultdict(list)
    ip_re = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    for i, line in enumerate(lines, 1):
        for ip in ip_re.findall(line):
            ip_lines[ip].append(i)
    for ip, lns in ip_lines.items():
        if len(lns) >= 3:  # lowered from 5 → 3
            anomalies.append(
                {
                    "type": "suspicious_ip",
                    "message": f"IP {ip} appears {len(lns)}x across log",
                    "lines": lns[:5],
                    "risk": "medium",
                }
            )

    # ── 3. Debug mode — broader detection ────────────────────────────────────
    # Catches: "debug = true", "DEBUG mode on", bare "[DEBUG]" log level lines,
    # and "level=debug" style config entries.
    debug_lines = [
        i + 1 for i, l in enumerate(lines)
        if re.search(
            r"(debug\s*[=:]\s*true"
            r"|DEBUG\s+mode\s+(on|enabled|true)"
            r"|\[\s*DEBUG\s*\]"
            r"|level\s*[=:]\s*['\"]?debug"
            r"|\bDEBUG\b)",
            l, re.IGNORECASE
        )
    ]
    if debug_lines:
        anomalies.append(
            {
                "type": "debug_mode",
                "message": f"Debug-level logging active ({len(debug_lines)} debug line(s)) — may expose internals in production",
                "risk": "medium",
                "lines": debug_lines[:5],
            }
        )

    # ── 4. High error rate (threshold: 3+ lines, >20%) ───────────────────────
    if len(non_empty) >= 3:  # lowered from 5 → 3
        error_line_count = sum(
            1 for l in non_empty
            if re.search(r"\b(ERROR|CRITICAL|FATAL)\b", l, re.IGNORECASE)
        )
        rate = error_line_count / len(non_empty)
        if rate > 0.20:  # lowered from 30% → 20%
            anomalies.append(
                {
                    "type": "high_error_rate",
                    "message": (
                        f"High error rate: {error_line_count}/{len(non_empty)} lines "
                        f"({int(rate * 100)}%) are errors"
                    ),
                    "risk": "high",
                    "lines": [],
                }
            )

    # ── 5. Multiple different exception types (new) ───────────────────────────
    exception_re = re.compile(
        r"\b(\w*Exception|\w*Error|\w*Fault|Traceback|SIGSEGV|OutOfMemory)\b"
    )
    exc_types: set[str] = set()
    exc_lines: list[int] = []
    for i, line in enumerate(lines, 1):
        m = exception_re.search(line)
        if m:
            exc_types.add(m.group(1))
            exc_lines.append(i)
    if len(exc_types) >= 2:
        anomalies.append(
            {
                "type": "multiple_exception_types",
                "message": f"Multiple exception types detected: {', '.join(sorted(exc_types)[:5])}",
                "lines": exc_lines[:5],
                "risk": "high",
            }
        )

    # ── 6. Authentication anomaly spike (new) ────────────────────────────────
    auth_fail_re = re.compile(
        r"(failed login|authentication failed|invalid (password|credentials?)|"
        r"unauthorized|access denied|login attempt|invalid token|401|403)",
        re.IGNORECASE,
    )
    auth_fail_lines = [i + 1 for i, l in enumerate(lines) if auth_fail_re.search(l)]
    if len(auth_fail_lines) >= 2:
        anomalies.append(
            {
                "type": "auth_failure_spike",
                "message": f"{len(auth_fail_lines)} authentication failure(s) detected — possible credential attack",
                "lines": auth_fail_lines[:5],
                "risk": "high",
            }
        )

    return anomalies


# ── Advanced: Cross-Entry Correlation ────────────────────────────────────────────
def correlate_entries(content: str) -> list[dict]:
    correlations: list[dict] = []
    lines = content.split("\n")

    # ── 1. Login followed by privileged action (expanded window: 15 lines) ───
    for i, line in enumerate(lines):
        if re.search(r"login|authenticated|session (start|open|created)", line, re.IGNORECASE):
            window = lines[i + 1 : i + 16]  # expanded from 6 → 16
            for j, wline in enumerate(window):
                if re.search(
                    r"(admin|root|sudo|DELETE|DROP|TRUNCATE|ALTER|GRANT|REVOKE|chmod|chown)",
                    wline, re.IGNORECASE
                ):
                    correlations.append(
                        {
                            "type": "privilege_escalation_pattern",
                            "message": (
                                f"Login at line {i + 1} followed by privileged action "
                                f"at line {i + j + 2}"
                            ),
                            "risk": "high",
                        }
                    )
                    break

    # ── 2. Error cluster: 3 errors within 5 lines ────────────────────────────
    error_positions = [
        i for i, l in enumerate(lines) if re.search(r"ERROR|FATAL|CRITICAL", l, re.IGNORECASE)
    ]
    if len(error_positions) >= 3:
        for idx in range(len(error_positions) - 2):
            span = error_positions[idx + 2] - error_positions[idx]
            if span <= 5:
                correlations.append(
                    {
                        "type": "error_cluster",
                        "message": (
                            f"3 errors within {span} lines starting at line "
                            f"{error_positions[idx] + 1} — possible cascade failure"
                        ),
                        "risk": "high",
                    }
                )
                break

    # ── 3. Secret/credential access followed by outbound connection (new) ────
    secret_re = re.compile(r"(api.?key|password|token|secret|credential)", re.IGNORECASE)
    net_re    = re.compile(r"(curl|wget|http|POST|GET|connect|socket|outbound)", re.IGNORECASE)
    for i, line in enumerate(lines):
        if secret_re.search(line):
            window = lines[i + 1 : i + 11]
            for j, wline in enumerate(window):
                if net_re.search(wline):
                    correlations.append(
                        {
                            "type": "credential_then_network",
                            "message": (
                                f"Credential access at line {i + 1} followed by "
                                f"network activity at line {i + j + 2} — possible exfiltration"
                            ),
                            "risk": "high",
                        }
                    )
                    break

    return correlations


# ── Fallback Insights ─────────────────────────────────────────────────────────────
def _fallback_insights(
    findings: list[dict], anomalies: list[dict], input_type: str
) -> list[str]:
    insights: list[str] = []
    critical = [f for f in findings if f["risk"] == "critical"]
    high = [f for f in findings if f["risk"] == "high"]
    medium = [f for f in findings if f["risk"] == "medium"]

    if critical:
        types = list({f["type"] for f in critical})
        lns = [str(f["line"]) for f in critical[:3]]
        insights.append(
            f"CRITICAL: {', '.join(types)} exposed at line(s) {', '.join(lns)} — rotate immediately"
        )
    if high:
        types = list({f["type"] for f in high})
        lns = [str(f["line"]) for f in high[:3]]
        insights.append(
            f"HIGH risk: {', '.join(types)} found at line(s) {', '.join(lns)} — investigate and revoke"
        )
    if medium:
        insights.append(
            f"{len(medium)} medium-risk pattern(s) detected (stack traces, debug info) — review before production"
        )
    if anomalies:
        anom_types = list({a["type"] for a in anomalies})
        insights.append(
            f"Anomalies detected: {', '.join(anom_types)} — review log patterns for systemic issues"
        )
    if not insights:
        insights.append("No critical issues found — routine security posture looks clean")
    return insights[:3]


# ── Gemini AI Insights ────────────────────────────────────────────────────────────
def get_ai_insights(
    input_type: str,
    content: str,
    findings: list[dict],
    anomalies: list[dict],
    correlations: list[dict],
) -> tuple[str, list[str]]:

    findings_text = json.dumps(findings[:10], indent=2)
    anomalies_text = json.dumps(anomalies[:5], indent=2)
    corr_text = json.dumps(correlations[:5], indent=2)

    chunks = chunk_content(content, chunk_size=3000)
    sample = chunks[0]

    prompt = f"""
You are a senior security analyst.

Analyze this {input_type} data.

CONTENT:
{sample}

FINDINGS:
{findings_text}

ANOMALIES:
{anomalies_text}

CORRELATIONS:
{corr_text}

Return ONLY JSON:
{{
  "summary": "one line summary",
  "insights": [
    "insight 1",
    "insight 2",
    "insight 3"
  ]
}}
"""

    try:
        response = client.models.generate_content(
            model="models/gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
            ),
        )

        raw = response.text

        print("\n==== GEMINI RAW RESPONSE ====\n", raw[:500])

        # Clean markdown if any
        raw = raw.replace("```json", "").replace("```", "").strip()

        # Extract JSON safely
        start = raw.find("{")
        end = raw.rfind("}") + 1

        if start == -1 or end == 0:
            raise ValueError("No JSON found in response")

        parsed = json.loads(raw[start:end])

        summary = parsed.get("summary", "").strip()
        insights = parsed.get("insights", [])

        if not summary or not isinstance(insights, list):
            raise ValueError("Invalid response format")

        return summary, insights[:3]

    except Exception as e:
        print(f"[ERROR] Gemini failed: {e}")
        return (
            f"{len(findings)} issue(s) detected in {input_type}",
            _fallback_insights(findings, anomalies, input_type),
        )


# ── Main Entry Point ──────────────────────────────────────────────────────────────
async def analyze_content(
    input_type: str,
    content: str,
    options: dict,
    client_id: str = "default",
) -> dict[str, Any]:

    # Rate limiting
    allowed, msg = check_rate_limit(client_id)
    if not allowed:
        return {"error": msg, "risk_level": "blocked", "action": "rate_limited"}

    # Chunk info for large files
    chunks = chunk_content(content)
    is_large = len(chunks) > 1

    # Step 1: Regex detection on full content
    findings = run_regex_detection(content)

    # Step 2: Log-specific parsing — merge without duplicating (same type + line)
    if input_type == "log":
        existing_keys = {(f["type"], f["line"]) for f in findings}
        for lf in parse_log(content):
            if (lf["type"], lf["line"]) not in existing_keys:
                findings.append(lf)
                existing_keys.add((lf["type"], lf["line"]))

    # Step 3: Advanced analysis (log-only)
    anomalies = detect_anomalies(content) if input_type == "log" else []
    correlations = correlate_entries(content) if input_type == "log" else []
    brute_force = detect_brute_force(content) if input_type == "log" else None

    # Step 4: Risk scoring
    anomaly_bonus = (
        3 if any(a["risk"] == "high" for a in anomalies + correlations) else 0
    )
    risk_score, risk_level = calculate_risk(findings, extra=anomaly_bonus)

    # Step 5: Gemini AI insights — run in thread to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    summary, insights = await loop.run_in_executor(
        None,
        get_ai_insights,
        input_type,
        content,
        findings,
        anomalies,
        correlations,
    )

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
            "high": len([f for f in findings if f["risk"] == "high"]),
            "medium": len([f for f in findings if f["risk"] == "medium"]),
            "low": len([f for f in findings if f["risk"] == "low"]),
        },
        "anomalies": anomalies,
        "correlations": correlations,
        "processing": {
            "chunks_processed": len(chunks),
            "large_file": is_large,
            "total_lines": content.count("\n") + 1,
        },
    }

    if brute_force:
        result["brute_force_detected"] = brute_force

    return result