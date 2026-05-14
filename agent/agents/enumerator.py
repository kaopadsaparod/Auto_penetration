"""
Enumerator agent — parses scan output using local Ollama (FREE).

This is the workhorse agent. It takes raw tool output and
extracts structured findings without any paid API calls.
"""
import json
import logging
from typing import Any

from agent.agents.llm_client import LLMClient, load_prompt

logger = logging.getLogger(__name__)





def parse_scan_findings(llm: LLMClient, raw_output: str, tool_name: str) -> list[dict]:
    """
    Parse raw tool output into structured findings using local LLM (FREE).

    Args:
        llm: LLMClient instance.
        raw_output: Raw stdout from a tool.
        tool_name: Name of the tool (nmap, gobuster, etc.)

    Returns:
        List of finding dicts.
    """
    if not raw_output or not raw_output.strip():
        return []

    # Truncate very long output to avoid overwhelming the local LLM
    max_chars = 4000
    truncated = raw_output[:max_chars]
    if len(raw_output) > max_chars:
        truncated += f"\n... [truncated, {len(raw_output) - max_chars} chars omitted]"

    prompt = load_prompt("enumerator_parse", tool_name=tool_name, output=truncated)

    try:
        findings = llm.query_local_json(prompt, system=load_prompt("enumerator_system"))
        if isinstance(findings, list):
            return findings
        elif isinstance(findings, dict):
            return [findings]
        return []
    except Exception as e:
        logger.warning("LLM parsing failed for %s output: %s", tool_name, e)
        # Fallback: return raw output as a single finding
        return [{"type": "raw", "detail": truncated[:500], "severity": "unknown"}]


def identify_services(llm: LLMClient, ports_data: list[dict]) -> list[dict]:
    """
    Analyze discovered ports/services for known vulnerabilities.

    Args:
        llm: LLMClient instance.
        ports_data: List of port dicts from nmap parser.

    Returns:
        List of service analysis dicts with potential CVEs.
    """
    if not ports_data:
        return []

    prompt = load_prompt("enumerator_services", services_json=json.dumps(ports_data, indent=2))

    try:
        return llm.query_local_json(prompt, system=load_prompt("enumerator_system"))
    except Exception as e:
        logger.warning("Service identification failed: %s", e)
        return []
