"""
AI Pentesting Agent — Main ReAct Loop.

This is the orchestration engine that ties everything together.
Implements a proper Reason-Act-Observe cycle (Fix #21).

Flow:
  1. OBSERVE  — Get next pending node from PTT
  2. SAFETY   — Validate command through guardrails
  3. ACT      — Run the tool
  4. PARSE    — Extract structured findings (Ollama, FREE)
  5. REASON   — Evaluate findings, decide significance (Ollama, FREE)
  6. PLAN     — If escalation needed → call Gemini (FREE TIER)
  7. EXPAND   — Create child nodes in PTT
  8. REPEAT   — Until done, budget exhausted, or max iterations
"""

import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.config import load_config, ConfigError
from agent.logger import setup_logger
from agent.ptt import PentestNode, PTTStore
from agent.agents.llm_client import LLMClient
from agent.agents.enumerator import parse_scan_findings, identify_services
from agent.agents.planner import create_attack_plan
from agent.agents.reasoner import reason_about_findings, generate_next_nodes
from agent.agents.exploiter import should_attempt_exploit, generate_exploit
from agent.safety.guardrails import safety_check
from agent.tools.nmap_tool import run_nmap, run_nmap_vuln
from agent.tools.gobuster_tool import run_gobuster_dir
from agent.tools.sqlmap_tool import run_sqlmap
from agent.tools.msf_tool import run_msf_module, run_msf_search
from agent.tools.shell_tool import run_shell

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# Tool dispatcher — Fix #9 (was referenced but never defined)
# ════════════════════════════════════════════════════════════════

TOOL_REGISTRY = {
    "nmap": lambda target, cmd, cfg: run_nmap(
        target, timeout=cfg["safety"]["max_subprocess_timeout"]
    ),
    "nmap_vuln": lambda target, cmd, cfg: run_nmap_vuln(
        target, timeout=cfg["safety"]["max_subprocess_timeout"]
    ),
    "gobuster": lambda target, cmd, cfg: run_gobuster_dir(
        f"http://{target}", timeout=cfg["safety"]["max_subprocess_timeout"]
    ),
    "sqlmap": lambda target, cmd, cfg: run_sqlmap(
        cmd, timeout=cfg["safety"]["max_subprocess_timeout"]
    ),
    "msf_search": lambda target, cmd, cfg: run_msf_search(cmd),
}


def run_tool(tool_name: str, command: str, target: str, config: dict):
    """
    Dispatch to the appropriate tool wrapper.

    Args:
        tool_name: Name of the tool (must be in TOOL_REGISTRY).
        command: The command string (used for some tools).
        target: Target IP address.
        config: Full config dict.

    Returns:
        ToolResult from the tool wrapper.
    """
    if tool_name in TOOL_REGISTRY:
        return TOOL_REGISTRY[tool_name](target, command, config)

    # Fallback: try to run as a generic shell command
    logger.warning("Unknown tool '%s', falling back to shell executor", tool_name)
    parts = command.split() if command else [tool_name, target]
    return run_shell(parts, timeout=config["safety"]["max_subprocess_timeout"])


# ════════════════════════════════════════════════════════════════
# Initial recon seed — creates the first PTT nodes
# ════════════════════════════════════════════════════════════════

def seed_initial_recon(ptt: PTTStore, target_ip: str) -> None:
    """Create the initial recon nodes if PTT is empty."""
    if ptt.get_stats()["total_nodes"] > 0:
        logger.info("PTT already has nodes, skipping seed")
        return

    logger.info("Seeding initial recon nodes for target: %s", target_ip)

    # Node 1: Quick nmap scan
    ptt.save(PentestNode(
        phase="recon",
        tool_used="nmap",
        command_run=f"nmap -sV -oX - {target_ip} -p 1-1000",
        notes="Initial service version scan — top 1000 ports",
    ))

    # Node 2: Full port scan (runs in parallel or after quick scan)
    ptt.save(PentestNode(
        phase="recon",
        tool_used="nmap",
        command_run=f"nmap -sV -oX - {target_ip} -p 1-65535",
        notes="Full port scan — all 65535 ports",
    ))

    logger.info("Seeded 2 initial recon nodes")


# ════════════════════════════════════════════════════════════════
# Main ReAct loop
# ════════════════════════════════════════════════════════════════

def react_loop(config: dict) -> dict:
    """
    Main Reason-Act-Observe loop.

    Args:
        config: Validated config dict.

    Returns:
        Summary dict with run statistics.
    """
    target_ip = config["target"]["ip"]
    max_iterations = config["budget"]["max_iterations"]

    # Initialize components
    ptt = PTTStore()
    llm = LLMClient(config)
    attack_plan = []

    # Seed initial recon if this is a fresh run
    seed_initial_recon(ptt, target_ip)

    logger.info("=" * 60)
    logger.info("Starting ReAct loop — target: %s, max iterations: %d",
                target_ip, max_iterations)
    logger.info("=" * 60)

    for iteration in range(max_iterations):
        logger.info("─── Iteration %d/%d ───", iteration + 1, max_iterations)

        # ── 1. OBSERVE — Get next pending node ───────────────
        node = ptt.get_next_pending()
        if not node:
            logger.info("No more pending nodes — run complete")
            break

        # Check budget before proceeding
        if llm.tracker.budget_exhausted:
            logger.warning("Budget exhausted — stopping")
            break

        # Mark as running
        node.status = "running"
        ptt.save(node)
        logger.info(
            "Processing node %s: phase=%s, tool=%s",
            node.id, node.phase, node.tool_used,
        )

        # ── 2. SAFETY — Validate command ─────────────────────
        command = node.command_run or ""
        approved, reason = safety_check(
            command, config, token_tracker=llm.tracker,
        )

        if not approved:
            logger.warning("Safety rejected: %s — %s", command[:80], reason)
            node.status = "skipped"
            node.error_message = f"Safety: {reason}"
            ptt.save(node)
            continue

        # ── 3. ACT — Run the tool ────────────────────────────
        logger.info("Executing: %s", command[:100])
        try:
            result = run_tool(node.tool_used or "shell", command, target_ip, config)
        except Exception as e:
            logger.error("Tool execution failed: %s", e)
            node.status = "failed"
            node.error_message = str(e)
            ptt.save(node)
            continue

        node.raw_output = result.raw[:10000] if result.raw else None  # Cap storage

        if not result.success and not result.raw:
            node.status = "failed"
            node.error_message = result.error
            ptt.save(node)
            logger.warning("Tool failed: %s", result.error)
            continue

        # ── 4. PARSE — Extract findings (Ollama, FREE) ──────
        # Use tool's built-in parser first, LLM as fallback
        if result.findings:
            findings = result.findings
        else:
            findings = parse_scan_findings(llm, result.raw, node.tool_used or "unknown")

        node.findings = findings
        node.status = "success"

        # ── 5. REASON — Evaluate findings (Ollama, FREE) ────
        reasoning = reason_about_findings(llm, node, findings)

        node.next_hypotheses = [
            step.get("action", "") for step in reasoning.get("next_steps", [])
        ]
        node.tokens_used = llm.tracker.local_tokens  # snapshot

        # ── 6. PLAN — Escalate to Gemini if needed ───────────
        if reasoning.get("escalate_to_paid") and not llm.tracker.budget_exhausted:
            logger.info("Escalating to Gemini for deeper analysis")

            if not attack_plan:
                attack_plan = create_attack_plan(llm, findings)

            # Check if we should attempt exploitation
            if should_attempt_exploit(findings):
                logger.info("CVE/vuln match found — generating exploit plan")
                for f in findings:
                    exploit_plan = generate_exploit(
                        llm,
                        service=f.get("service", "unknown"),
                        version=f.get("version", ""),
                        cve=f.get("cve", None),
                    )
                    if exploit_plan.get("commands"):
                        # Create exploit nodes
                        for cmd in exploit_plan["commands"][:3]:
                            ptt.save(PentestNode(
                                phase="exploit",
                                status="pending",
                                parent_id=node.id,
                                tool_used="msf" if "msf" in cmd.lower() else "shell",
                                command_run=cmd,
                                notes=exploit_plan.get("approach", ""),
                            ))
                        break  # One exploit attempt at a time

        # ── 7. EXPAND — Create child nodes ───────────────────
        if not reasoning.get("dead_end"):
            child_nodes = generate_next_nodes(llm, node, reasoning, target_ip)
            for child in child_nodes:
                ptt.save(child)

        ptt.save(node)

        # Print progress
        stats = ptt.get_stats()
        budget = llm.tracker.get_summary()
        logger.info(
            "Progress: %d nodes (%d pending, %d success, %d failed) | "
            "Budget: %d/%d tokens, %d/%d API calls",
            stats["total_nodes"], stats["pending"], stats["success"],
            stats["failed"], budget["paid_tokens"],
            budget["paid_tokens"] + budget["budget_remaining"],
            budget["api_calls"],
            budget["api_calls"] + budget["calls_remaining"],
        )

    # ── Final summary ────────────────────────────────────────
    final_stats = ptt.get_stats()
    budget_summary = llm.tracker.get_summary()

    summary = {
        "target": target_ip,
        "iterations_run": min(iteration + 1, max_iterations),
        "ptt_stats": final_stats,
        "budget": budget_summary,
        "attack_plan": attack_plan,
    }

    logger.info("=" * 60)
    logger.info("ReAct loop complete")
    logger.info("Nodes: %d total, %d success, %d failed, %d pending",
                final_stats["total_nodes"], final_stats["success"],
                final_stats["failed"], final_stats["pending"])
    logger.info("Budget: %d paid tokens, %d API calls",
                budget_summary["paid_tokens"], budget_summary["api_calls"])
    logger.info("=" * 60)

    ptt.close()
    return summary


# ════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════

def main():
    """Main entry point — load config and start the ReAct loop."""
    # Setup logging first
    setup_logger()

    try:
        config = load_config()
    except (ConfigError, FileNotFoundError) as e:
        logger.critical("Config error: %s", e)
        sys.exit(1)

    logger.info("Config loaded — target: %s", config["target"]["ip"])
    logger.info("Budget: %d max tokens, %d max API calls",
                config["budget"]["max_tokens_per_run"],
                config["budget"]["max_api_calls"])

    try:
        summary = react_loop(config)
        # Export PTT for reporting
        export_path = Path("data/run_summary.json")
        export_path.parent.mkdir(parents=True, exist_ok=True)
        with open(export_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        logger.info("Run summary exported to %s", export_path)

    except KeyboardInterrupt:
        logger.info("Run interrupted by user (Ctrl+C)")
    except Exception as e:
        logger.critical("Fatal error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
