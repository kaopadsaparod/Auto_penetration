"""
Metasploit RPC tool wrapper.
Interacts with msfrpcd for exploit execution.
"""
import logging
import json
from typing import Optional
from agent.tools.base import ToolResult, run_subprocess, sanitize_arg, validate_target

logger = logging.getLogger(__name__)


def run_msf_module(
    module_type: str,
    module_name: str,
    options: dict,
    timeout: int = 120,
) -> ToolResult:
    """
    Run a Metasploit module via msfconsole resource script.

    Args:
        module_type: "exploit", "auxiliary", or "post"
        module_name: e.g., "exploit/multi/handler"
        options: Dict of module options (RHOSTS, LHOST, etc.)
        timeout: Seconds before killing.

    Returns:
        ToolResult with module output.
    """
    # Build msfconsole resource commands
    rc_lines = [f"use {module_type}/{module_name}"]
    for key, value in options.items():
        key = sanitize_arg(str(key))
        value = sanitize_arg(str(value))
        rc_lines.append(f"set {key} {value}")
    rc_lines.append("run")
    rc_lines.append("exit")
    rc_script = "\n".join(rc_lines)

    # Execute via msfconsole -x (inline commands)
    cmd = ["msfconsole", "-q", "-x", rc_script]
    result = run_subprocess(cmd, timeout=timeout)

    # Parse for session creation or loot
    if result.raw:
        findings = []
        for line in result.raw.split("\n"):
            line = line.strip()
            if "session" in line.lower() and "opened" in line.lower():
                findings.append({"type": "session", "detail": line})
            elif "meterpreter" in line.lower():
                findings.append({"type": "meterpreter", "detail": line})
            elif "found" in line.lower() or "vulnerable" in line.lower():
                findings.append({"type": "vuln_confirmed", "detail": line})
        result.findings = findings

    return result


def run_msf_search(query: str, timeout: int = 60) -> ToolResult:
    """Search Metasploit modules for a given query."""
    query = sanitize_arg(query)
    cmd = ["msfconsole", "-q", "-x", f"search {query}; exit"]
    return run_subprocess(cmd, timeout=timeout)
