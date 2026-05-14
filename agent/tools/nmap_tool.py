"""
Nmap tool wrapper.

Returns structured scan results with proper XML parsing.
Uses list-based subprocess calls to prevent command injection.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Optional

from agent.tools.base import (
    ToolResult,
    run_subprocess,
    validate_ip,
    validate_ports,
    validate_target,
)

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# XML Parser — the missing parse_nmap_xml() (Fix #4)
# ════════════════════════════════════════════════════════════════

def parse_nmap_xml(xml_string: str) -> list[dict]:
    """
    Parse nmap XML output (-oX -) into structured port/service dicts.

    Returns:
        List of dicts, each with:
          - port (int)
          - protocol (str)
          - state (str)
          - service (str)
          - version (str)
          - product (str)
          - extra_info (str)
    """
    if not xml_string or not xml_string.strip():
        logger.warning("Empty nmap XML output")
        return []

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.error("Failed to parse nmap XML: %s", e)
        return []

    results = []

    for host in root.findall("host"):
        # Get host address
        addr_elem = host.find("address")
        host_addr = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

        # Get host status
        status_elem = host.find("status")
        host_status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        # Parse ports
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            port_info = {
                "host": host_addr,
                "host_status": host_status,
                "port": int(port_elem.get("portid", 0)),
                "protocol": port_elem.get("protocol", "tcp"),
                "state": "unknown",
                "service": "unknown",
                "version": "",
                "product": "",
                "extra_info": "",
            }

            # Port state
            state_elem = port_elem.find("state")
            if state_elem is not None:
                port_info["state"] = state_elem.get("state", "unknown")

            # Service info
            service_elem = port_elem.find("service")
            if service_elem is not None:
                port_info["service"] = service_elem.get("name", "unknown")
                port_info["product"] = service_elem.get("product", "")
                port_info["version"] = service_elem.get("version", "")
                port_info["extra_info"] = service_elem.get("extrainfo", "")

            results.append(port_info)

    # Only keep open ports by default
    open_ports = [p for p in results if p["state"] == "open"]
    logger.info(
        "Parsed nmap XML: %d total ports, %d open",
        len(results), len(open_ports),
    )
    return open_ports


# ════════════════════════════════════════════════════════════════
# Nmap scan functions
# ════════════════════════════════════════════════════════════════

def run_nmap(
    target: str,
    ports: str = "1-1000",
    scan_type: str = "service",
    timeout: int = 300,
    extra_args: Optional[list[str]] = None,
) -> ToolResult:
    """
    Run an nmap scan with structured output.

    SECURITY: Uses list-based subprocess call (never f-string + split).

    Args:
        target:    IP address or hostname to scan.
        ports:     Port specification (e.g., "1-1000", "22,80,443").
        scan_type: One of "service" (-sV), "os" (-O), "quick" (-F),
                   "vuln" (--script vuln), "full" (-A).
        timeout:   Seconds before killing the scan.
        extra_args: Additional nmap arguments as a list.

    Returns:
        ToolResult with parsed open ports in `findings`.
    """
    # ── Validate inputs (Fix #1: no f-string injection) ──────
    target = validate_target(target)
    ports = validate_ports(ports)

    # ── Build command as a list ──────────────────────────────
    cmd = ["nmap"]

    # Scan type flags
    scan_flags = {
        "service": ["-sV"],
        "os": ["-sV", "-O"],
        "quick": ["-F"],
        "vuln": ["-sV", "--script", "vuln"],
        "full": ["-A"],
    }
    cmd.extend(scan_flags.get(scan_type, ["-sV"]))

    # Output as XML to stdout for parsing
    cmd.extend(["-oX", "-"])

    # Port specification
    cmd.extend(["-p", ports])

    # Extra arguments (each must be sanitized)
    if extra_args:
        for arg in extra_args:
            # Basic sanity check — no shell metacharacters
            if any(c in arg for c in ";|&$`\\"):
                logger.warning("Rejected dangerous nmap arg: %s", arg)
                continue
            cmd.append(arg)

    # Target goes last
    cmd.append(target)

    # ── Execute ──────────────────────────────────────────────
    result = run_subprocess(cmd, timeout=timeout)

    # ── Parse XML output into structured findings ────────────
    if result.raw:
        result.findings = parse_nmap_xml(result.raw)

    return result


def run_nmap_quick(target: str, timeout: int = 120) -> ToolResult:
    """Quick scan — top 100 ports, fast."""
    return run_nmap(target, ports="1-1000", scan_type="quick", timeout=timeout)


def run_nmap_full(target: str, timeout: int = 600) -> ToolResult:
    """Full scan — all ports with version + OS detection."""
    return run_nmap(
        target, ports="1-65535", scan_type="full", timeout=timeout
    )


def run_nmap_vuln(
    target: str, ports: str = "1-1000", timeout: int = 600
) -> ToolResult:
    """Vulnerability scan — runs NSE vuln scripts."""
    return run_nmap(target, ports=ports, scan_type="vuln", timeout=timeout)
