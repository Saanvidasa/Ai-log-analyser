import re
from typing import Any

# Log-specific risk patterns beyond the generic ones
LOG_PATTERNS = [
    {
        "name": "hardcoded_secret",
        "regex": r"(secret|private_key|access_key|client_secret)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
        "risk": "critical",
        "description": "Hardcoded secret in log"
    },
    {
        "name": "debug_mode",
        "regex": r"(DEBUG\s+mode\s+(enabled|on|true)|debug=true)",
        "risk": "medium",
        "description": "Debug mode enabled — may expose internals"
    },
    {
        "name": "stack_trace",
        "regex": r"(Traceback \(most recent|Exception in thread|at \w[\w.]+\(\w+\.java:\d+\)|NullPointerException|StackOverflowError)",
        "risk": "medium",
        "description": "Stack trace exposes internal implementation"
    },
    {
        "name": "db_connection_string",
        "regex": r"(jdbc:|mongodb://|postgresql://|mysql://|redis://)[^\s\"']{10,}",
        "risk": "critical",
        "description": "Database connection string exposed"
    },
    {
        "name": "aws_key",
        "regex": r"(AKIA|ASIA)[A-Z0-9]{16}",
        "risk": "critical",
        "description": "AWS access key exposed"
    },
    {
        "name": "private_key_header",
        "regex": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "risk": "critical",
        "description": "Private key material in log"
    },
    {
        "name": "sql_error",
        "regex": r"(SQL syntax error|ORA-\d{5}|mysql_fetch|pg_query|syntax error.*SQL)",
        "risk": "medium",
        "description": "SQL error may reveal schema/query structure"
    },
    {
        "name": "path_disclosure",
        "regex": r"(/home/[\w/]+|/var/www/[\w/]+|C:\\Users\\[\w\\]+|/etc/[\w/]+)",
        "risk": "low",
        "description": "Internal file path disclosed"
    },
    {
        "name": "suspicious_ip",
        "regex": r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",
        "risk": "low",
        "description": "Internal IP address in log"
    },
]

def parse_log(content: str) -> list[dict[str, Any]]:
    """Parse log content line by line and return findings."""
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for pattern in LOG_PATTERNS:
            match = re.search(pattern["regex"], line, re.IGNORECASE)
            if match:
                value = match.group(0)
                masked = mask_log_value(value, pattern["name"])
                findings.append({
                    "type": pattern["name"],
                    "risk": pattern["risk"],
                    "line": line_num,
                    "value": masked,
                    "description": pattern["description"],
                    "raw_line": line.strip()[:120]
                })

    return findings

def classify_log_risks(findings: list[dict]) -> dict[str, Any]:
    """Group findings and return a structured risk breakdown."""
    breakdown = {"critical": [], "high": [], "medium": [], "low": []}
    for finding in findings:
        risk = finding.get("risk", "low")
        if risk in breakdown:
            breakdown[risk].append(finding)
    return breakdown

def mask_log_value(value: str, pattern_name: str) -> str:
    """Mask sensitive values before returning to client."""
    sensitive = {"hardcoded_secret", "db_connection_string", "aws_key", "private_key_header"}
    if pattern_name in sensitive:
        return "***REDACTED***"
    if len(value) > 10:
        return value[:4] + "****" + value[-4:]
    return "****"
