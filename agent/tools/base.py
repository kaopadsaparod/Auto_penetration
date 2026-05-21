"""
Base tool infrastructure.

Provides:
  - Input validation (IPs, ports, URLs) to prevent command injection
  - ToolResult dataclass for consistent output shape
  - Safe subprocess execution wrapper
"""

import ipaddress
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# Input validation — prevents command injection (Fix #1, #2)
# ════════════════════════════════════════════════════════════════

# Strict patterns — only allow clean inputs
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
CIDR_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}$"
)
PORT_RANGE_PATTERN = re.compile(r"^(\d{1,5})(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")
URL_PATTERN = re.compile(r"^https?://[a-zA-Z0-9\-\.]+(:\d+)?(/[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]*)?$")

# Characters that NEVER belong in tool arguments
SHELL_DANGEROUS = set(";|&$`\\!{}()")


class ValidationError(Exception):
    """Raised when input fails security validation."""
    pass


def validate_ip(target: str) -> str:
    """
    Validate an IP address string. Rejects anything that isn't
    a clean IPv4 address — no shell metacharacters, no hostnames.

    Returns:
        The validated IP string.

    Raises:
        ValidationError: If input is not a valid IPv4 address.
    """
    target = target.strip()
    if not IP_PATTERN.match(target):
        raise ValidationError(f"Invalid IP address: '{target}'")
    # Double-check with stdlib
    try:
        ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError as e:
        raise ValidationError(f"Invalid IP address: '{target}' — {e}")
    return target


def validate_target(target: str) -> str:
    """
    Validate a target — can be IP address or hostname.
    Rejects shell metacharacters.

    Returns:
        The validated target string.

    Raises:
        ValidationError: If input contains dangerous characters.
    """
    target = target.strip()
    # Check for shell injection characters
    if any(c in SHELL_DANGEROUS for c in target):
        raise ValidationError(
            f"Target contains dangerous characters: '{target}'"
        )
    # Must be a valid IP or hostname
    if IP_PATTERN.match(target):
        return validate_ip(target)
    if HOSTNAME_PATTERN.match(target) and len(target) <= 253:
        return target
    raise ValidationError(f"Invalid target (not IP or hostname): '{target}'")


def validate_ports(ports: str) -> str:
    """
    Validate a port specification string (e.g., "1-1000", "22,80,443").

    Returns:
        The validated port string.

    Raises:
        ValidationError: If input is not a valid port specification.
    """
    ports = ports.strip()
    if not PORT_RANGE_PATTERN.match(ports):
        raise ValidationError(f"Invalid port specification: '{ports}'")

    # Check all port numbers are in valid range (1-65535)
    for part in ports.split(","):
        for num_str in part.split("-"):
            num = int(num_str)
            if num < 1 or num > 65535:
                raise ValidationError(
                    f"Port out of range (1-65535): {num}"
                )
    return ports


def validate_url(url: str) -> str:
    """
    Validate a URL — must be http or https, no shell injection.

    Returns:
        The validated URL string.

    Raises:
        ValidationError: If URL is invalid or contains dangerous characters.
    """
    url = url.strip()
    if not URL_PATTERN.match(url):
        raise ValidationError(f"Invalid URL: '{url}'")
    return url


def sanitize_arg(arg: str) -> str:
    """
    Sanitize a generic command argument.
    Rejects anything with shell metacharacters.
    """
    arg = arg.strip()
    if any(c in SHELL_DANGEROUS for c in arg):
        raise ValidationError(
            f"Argument contains dangerous characters: '{arg}'"
        )
    return arg


# ════════════════════════════════════════════════════════════════
# ToolResult — consistent output shape for all tools
# ════════════════════════════════════════════════════════════════

@dataclass
class ToolResult:
    """
    Standard result from any tool wrapper.

    All tool wrappers MUST return this shape so agents
    don't need per-tool parsing logic.
    """
    command: str                        # The exact command that was run
    findings: list = field(default_factory=list)  # Parsed structured data
    raw: str = ""                       # Raw stdout
    error: Optional[str] = None         # stderr or exception message
    duration: float = 0.0               # Seconds elapsed
    return_code: int = -1               # Process return code

    @property
    def success(self) -> bool:
        return self.error is None and self.return_code == 0


# ════════════════════════════════════════════════════════════════
# Safe subprocess execution
# ════════════════════════════════════════════════════════════════

def run_subprocess(
    cmd: list[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
) -> ToolResult:
    """
    Execute a command as a subprocess with safety controls.

    IMPORTANT: `cmd` must be a LIST of strings, never a single
    string. This prevents shell injection.

    Args:
        cmd:     Command as a list (e.g., ["nmap", "-sV", "10.10.10.1"])
        timeout: Max seconds before killing the process.
        cwd:     Working directory for the command.

    Returns:
        ToolResult with stdout, stderr, return code, and timing.
    """
    command_str = " ".join(cmd)
    logger.info("Running: %s (timeout=%ds)", command_str, timeout)

    # ── Dry-Run Mock Execution ───────────────────────────────
    # Dynamically resolve configuration to check if dry_run is enabled
    try:
        from agent.config import load_config
        cfg = load_config()
        dry_run = cfg.get("safety", {}).get("dry_run", False)
    except Exception:
        dry_run = False

    if dry_run:
        logger.info("[DRY RUN] Intercepted execution of: %s", command_str)
        # Generate premium mock output depending on the command
        binary = cmd[0].lower()
        mock_stdout = ""
        mock_stderr = ""
        mock_rc = 0

        if "nmap" in binary:
            # Check if it is nmap_vuln or standard service scan
            if "--script" in command_str and "vuln" in command_str:
                mock_stdout = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.49"/>
        <script id="vuln" output="CVE-2021-41773 Apache RCE vulnerable!"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
            else:
                mock_stdout = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.6p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.49"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        elif "gobuster" in binary:
            mock_stdout = """
/index.html (Status: 200) [Size: 1530]
/admin (Status: 200) [Size: 450]
/secret.txt (Status: 200) [Size: 85]
"""
        elif "sqlmap" in binary:
            mock_stdout = "[INFO] GET parameter 'id' is vulnerable to SQL injection (UNION query)"
        else:
            mock_stdout = f"[DRY RUN Mock Output] Executed command: {command_str}"

        return ToolResult(
            command=command_str,
            raw=mock_stdout,
            error=None,
            duration=0.01,
            return_code=0,
        )

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            # NEVER use shell=True — that enables injection
        )
        duration = time.time() - start

        tool_result = ToolResult(
            command=command_str,
            raw=result.stdout,
            error=result.stderr.strip() if result.stderr.strip() else None,
            duration=duration,
            return_code=result.returncode,
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        logger.warning("Command timed out after %ds: %s", timeout, command_str)
        tool_result = ToolResult(
            command=command_str,
            error=f"Command timed out after {timeout}s",
            duration=duration,
            return_code=-1,
        )

    except FileNotFoundError:
        duration = time.time() - start
        logger.error("Command not found: %s", cmd[0])
        tool_result = ToolResult(
            command=command_str,
            error=f"Command not found: {cmd[0]}. Is it installed?",
            duration=duration,
            return_code=-1,
        )

    except Exception as e:
        duration = time.time() - start
        logger.error("Subprocess error: %s", str(e))
        tool_result = ToolResult(
            command=command_str,
            error=f"Unexpected error: {str(e)}",
            duration=duration,
            return_code=-1,
        )

    logger.info(
        "Finished in %.1fs (rc=%d, output=%d chars)",
        tool_result.duration,
        tool_result.return_code,
        len(tool_result.raw),
    )
    return tool_result
