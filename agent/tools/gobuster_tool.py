"""
Gobuster tool wrapper.

Directory/vhost brute-force scanner with structured output parsing.
"""

import logging
import re
from typing import Optional

from agent.tools.base import (
    ToolResult,
    run_subprocess,
    sanitize_arg,
    validate_url,
)

logger = logging.getLogger(__name__)


def parse_gobuster_output(raw: str) -> list[dict]:
    """
    Parse gobuster stdout into structured findings.

    Returns list of dicts with:
      - path (str)
      - status (int)
      - size (int)
    """
    findings = []
    # Gobuster output format: /path (Status: 200) [Size: 1234]
    pattern = re.compile(
        r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]",
        re.MULTILINE,
    )
    for match in pattern.finditer(raw):
        findings.append({
            "path": match.group(1),
            "status": int(match.group(2)),
            "size": int(match.group(3)),
        })

    # Also handle newer gobuster format: /path               [Status: 200, Size: 1234, ...]
    pattern2 = re.compile(
        r"^(/\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
        re.MULTILINE,
    )
    for match in pattern2.finditer(raw):
        path = match.group(1)
        # Avoid duplicates
        if not any(f["path"] == path for f in findings):
            findings.append({
                "path": path,
                "status": int(match.group(2)),
                "size": int(match.group(3)),
            })

    logger.info("Parsed gobuster output: %d findings", len(findings))
    return findings


def run_gobuster_dir(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    threads: int = 10,
    timeout: int = 300,
    extra_args: Optional[list[str]] = None,
) -> ToolResult:
    """
    Run gobuster in directory brute-force mode.

    Args:
        url:        Target URL (e.g., "http://10.10.10.1:80")
        wordlist:   Path to wordlist file.
        extensions: Comma-separated extensions (e.g., "php,html,txt")
        threads:    Number of concurrent threads.
        timeout:    Seconds before killing.
        extra_args: Additional gobuster arguments.

    Returns:
        ToolResult with discovered paths in `findings`.
    """
    url = validate_url(url)
    wordlist = sanitize_arg(wordlist)

    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "--no-color",
        "-q",  # Quiet mode — less noise
    ]

    if extensions:
        extensions = sanitize_arg(extensions)
        cmd.extend(["-x", extensions])

    if extra_args:
        for arg in extra_args:
            cmd.append(sanitize_arg(arg))

    result = run_subprocess(cmd, timeout=timeout)

    if result.raw:
        result.findings = parse_gobuster_output(result.raw)

    return result


def run_gobuster_vhost(
    url: str,
    wordlist: str = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    threads: int = 10,
    timeout: int = 300,
) -> ToolResult:
    """
    Run gobuster in virtual host discovery mode.

    Args:
        url:      Target URL.
        wordlist: Subdomain wordlist path.
        threads:  Concurrent threads.
        timeout:  Seconds before killing.

    Returns:
        ToolResult with discovered vhosts in `findings`.
    """
    url = validate_url(url)
    wordlist = sanitize_arg(wordlist)

    cmd = [
        "gobuster", "vhost",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "--no-color",
        "-q",
    ]

    result = run_subprocess(cmd, timeout=timeout)

    if result.raw:
        result.findings = parse_gobuster_output(result.raw)

    return result
