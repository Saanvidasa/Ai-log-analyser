import re
from typing import Any

# ── Log Parser ───────────────────────────────────────────────────────────────────
# Patterns here are ONLY for log-specific signals that analyzer.py does NOT already cover.
# Do NOT add aws_key, db_conn, or secret here — those are handled by the main PATTERNS dict.
LOG_PATTERNS = [
    {
        "name": "private_key_header",
        "regex": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "risk": "critical",
        "description": "Private key material in log",
    },
    {
        "name": "sql_error",
        "regex": r"(SQL syntax error|ORA-\d{5}|mysql_fetch|pg_query|syntax error.*SQL)",
        "risk": "medium",
        "description": "SQL error may reveal schema/query structure",
    },
    {
        "name": "path_disclosure",
        "regex": r"(/home/[\w/]+|/var/www/[\w/]+|C:\\Users\\[\w\\]+|/etc/[\w/]+)",
        "risk": "low",
        "description": "Internal file path disclosed",
    },
    {
        "name": "internal_ip",
        # Private RFC-1918 ranges only — the main regex already catches all IPs at low risk,
        # so we flag private-network IPs separately as a log-specific signal.
        "regex": (
            r"\b("
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r")\b"
        ),
        "risk": "low",
        "description": "Internal (RFC-1918) IP address in log",
    },
    {
        "name": "debug_flag",
        "regex": r"(DEBUG\s+mode\s+(enabled|on|true)|debug\s*=\s*true)",
        "risk": "medium",
        "description": "Debug mode enabled — may expose internals",
    },
    {
        "name": "stack_trace_detail",
        "regex": (
            r"(Traceback \(most recent call last\)"
            r"|Exception in thread"
            r"|NullPointerException"
            r"|StackOverflowError)"
        ),
        "risk": "medium",
        "description": "Stack trace exposes internal implementation details",
    },
]


def parse_log(content: str) -> list[dict[str, Any]]:
    """Parse log content line by line and return findings not covered by the main regex pass."""
    findings: list[dict[str, Any]] = []
    lines = content.split("\n")
    seen: set[str] = set()  # dedup: (pattern_name, line_number)

    for line_num, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for pattern in LOG_PATTERNS:
            match = re.search(pattern["regex"], line, re.IGNORECASE)
            if match:
                key = f"{pattern['name']}:{line_num}"
                if key in seen:
                    continue
                seen.add(key)
                value = match.group(0)
                findings.append(
                    {
                        "type": pattern["name"],
                        "risk": pattern["risk"],
                        "line": line_num,
                        "value": mask_log_value(value, pattern["name"]),
                        "description": pattern["description"],
                        "raw_line": line.strip()[:120],
                    }
                )

    return findings


def classify_log_risks(findings: list[dict]) -> dict[str, Any]:
    """Group findings by risk level."""
    breakdown: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for finding in findings:
        risk = finding.get("risk", "low")
        if risk in breakdown:
            breakdown[risk].append(finding)
    return breakdown


def mask_log_value(value: str, pattern_name: str) -> str:
    """Mask sensitive values before returning to client."""
    sensitive = {"private_key_header"}
    if pattern_name in sensitive:
        return "***REDACTED***"
    if len(value) > 10:
        return value[:4] + "****" + value[-4:]
    return "****"