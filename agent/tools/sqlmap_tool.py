"""
SQLMap tool wrapper.
SQL injection scanner with batch mode and structured output.
"""
import logging
import re
from typing import Optional
from agent.tools.base import ToolResult, run_subprocess, sanitize_arg, validate_url

logger = logging.getLogger(__name__)


def parse_sqlmap_output(raw: str) -> list[dict]:
    """Parse sqlmap stdout for injection points and findings."""
    findings = []
    for line in raw.split("\n"):
        line = line.strip()
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            findings.append({"type": "injection", "detail": line})
        elif "back-end DBMS" in line:
            findings.append({"type": "database", "detail": line})
        elif "current user:" in line.lower():
            findings.append({"type": "user", "detail": line})
        elif "current user is DBA" in line:
            findings.append({"type": "privilege", "detail": line})
    return findings


def run_sqlmap(url: str, data: Optional[str] = None, level: int = 1,
               risk: int = 1, timeout: int = 300) -> ToolResult:
    """Run sqlmap in batch (non-interactive) mode."""
    url = validate_url(url)
    cmd = ["sqlmap", "-u", url, "--batch",
           "--level", str(max(1, min(5, level))),
           "--risk", str(max(1, min(3, risk))),
           "--threads", "4"]
    if data:
        cmd.extend(["--data", sanitize_arg(data)])
    result = run_subprocess(cmd, timeout=timeout)
    if result.raw:
        result.findings = parse_sqlmap_output(result.raw)
    return result
