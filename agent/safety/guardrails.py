"""
Safety guardrails — scope guard, budget guard, HITL approval.

Every command goes through safety_check() before execution.
This is non-negotiable and cannot be bypassed by the agent.
"""

import ipaddress
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# IP extraction — Fix #5 (was referenced but never written)
# ════════════════════════════════════════════════════════════════

IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def extract_ips(command: str) -> list[str]:
    """
    Extract all IPv4 addresses from a command string.

    Args:
        command: The command string to scan.

    Returns:
        List of IP address strings found in the command.
    """
    return IP_REGEX.findall(command)


# ════════════════════════════════════════════════════════════════
# Destructive command detection — Fix #6 (was referenced but never written)
# ════════════════════════════════════════════════════════════════

def is_destructive(command: str, config: dict) -> bool:
    """
    Check if a command is potentially destructive and requires
    human approval.

    Checks against:
      1. Absolute blocklist (never allow)
      2. Destructive keywords (require HITL approval)

    Args:
        command: The command string to check.
        config: Config dict with safety settings.

    Returns:
        True if the command is destructive (needs HITL), False if safe.
    """
    cmd_lower = command.lower()

    # Check destructive keywords from config
    destructive_keywords = config.get("safety", {}).get("destructive_keywords", [])
    for keyword in destructive_keywords:
        if keyword.lower() in cmd_lower:
            logger.warning("Destructive keyword detected: '%s' in command", keyword)
            return True

    return False


def is_blocked(command: str, config: dict) -> tuple[bool, str]:
    """
    Check if a command is in the absolute blocklist.
    Blocked commands are NEVER allowed, even with human approval.

    Returns:
        (is_blocked, reason) tuple.
    """
    cmd_lower = command.lower()
    blocked = config.get("safety", {}).get("blocked_commands", [])

    for pattern in blocked:
        if pattern.lower() in cmd_lower:
            reason = f"BLOCKED: Command contains forbidden pattern '{pattern}'"
            logger.error(reason)
            return True, reason

    return False, ""


# ════════════════════════════════════════════════════════════════
# Scope guard — CIDR-based IP validation
# ════════════════════════════════════════════════════════════════

def is_in_scope(ip_str: str, config: dict) -> bool:
    """
    Check if an IP address is within the allowed scope.

    Uses CIDR notation from config for proper subnet matching
    (not just string equality).

    Args:
        ip_str: IP address string to check.
        config: Config dict with parsed networks.

    Returns:
        True if the IP is within allowed scope.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ipaddress.AddressValueError:
        return False

    # Check against pre-parsed networks
    networks = config.get("_parsed_networks", [])
    if not networks:
        # Parse on the fly if not cached
        for cidr in config.get("target", {}).get("allowed_ips", []):
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

    return any(ip in network for network in networks)


# ════════════════════════════════════════════════════════════════
# Main safety check — the single entry point
# ════════════════════════════════════════════════════════════════

def safety_check(
    command: str,
    config: dict,
    token_tracker=None,
    skip_hitl: bool = False,
) -> tuple[bool, str]:
    """
    Complete safety check before executing any command.

    Checks in order:
      1. Absolute blocklist (instant reject, no override)
      2. Scope guard (all IPs in command must be in-scope)
      3. Budget guard (token/API call budget)
      4. HITL gate (for destructive commands, ask human)

    Args:
        command: Command string to validate.
        config: Full config dict.
        token_tracker: Optional TokenTracker for budget checking.
        skip_hitl: If True, skip human approval (for testing).

    Returns:
        (approved, reason) tuple.
    """
    if not command or not command.strip():
        return False, "Empty command"

    # ── 1. Absolute blocklist ────────────────────────────────
    blocked, reason = is_blocked(command, config)
    if blocked:
        return False, reason

    # ── 2. Scope guard ───────────────────────────────────────
    ips_in_command = extract_ips(command)
    for ip in ips_in_command:
        if not is_in_scope(ip, config):
            reason = f"SCOPE VIOLATION: IP {ip} is outside allowed range"
            logger.error(reason)
            return False, reason

    # ── 3. Budget guard ──────────────────────────────────────
    if token_tracker and token_tracker.budget_exhausted:
        reason = (
            f"BUDGET EXHAUSTED: "
            f"Tokens {token_tracker.paid_tokens}/{token_tracker.max_paid_tokens}, "
            f"Calls {token_tracker.api_calls}/{token_tracker.max_api_calls}"
        )
        logger.warning(reason)
        return False, reason

    # ── 4. HITL gate ─────────────────────────────────────────
    require_approval = config.get("safety", {}).get("require_human_approval", True)

    if is_destructive(command, config) and require_approval and not skip_hitl:
        print("\n" + "=" * 60)
        print("[HITL] Human-in-the-Loop Approval Required")
        print("=" * 60)
        print(f"Command: {command}")
        print(f"Reason:  Contains destructive/exploit keywords")
        print("=" * 60)

        try:
            approval = input("Approve this command? (y/n): ").strip().lower()
            if approval == "y":
                logger.info("HITL APPROVED: %s", command)
                return True, "Human approved"
            else:
                logger.info("HITL REJECTED: %s", command)
                return False, "Human rejected command"
        except (EOFError, KeyboardInterrupt):
            logger.info("HITL interrupted — rejecting command")
            return False, "HITL interrupted"

    return True, "OK"
