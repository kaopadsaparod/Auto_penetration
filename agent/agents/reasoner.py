"""
Reasoner agent — the missing "Reason" step of ReAct (Fix #21).

Evaluates findings BEFORE deciding next actions. Uses local Ollama (FREE).
This is what makes it a true ReAct loop instead of just Act-Parse.
"""
import json
import logging

from agent.agents.llm_client import LLMClient, load_prompt
from agent.ptt import PentestNode

logger = logging.getLogger(__name__)





def reason_about_findings(
    llm: LLMClient,
    node: PentestNode,
    findings: list[dict],
) -> dict:
    """
    Reason about findings to decide significance and next steps.

    This is the THINK step that was missing from the original plan.
    Uses local Ollama (FREE).

    Args:
        llm: LLMClient instance.
        node: The current PTT node.
        findings: Parsed findings from the tool.

    Returns:
        Dict with:
          - significance: "low", "medium", "high", "critical"
          - reasoning: str explaining the assessment
          - escalate_to_paid: bool — should we call Gemini for deeper analysis?
          - next_steps: list of dicts describing follow-up actions
          - dead_end: bool — should we stop exploring this branch?
    """
    if not findings:
        return {
            "significance": "low",
            "reasoning": "No findings from this step.",
            "escalate_to_paid": False,
            "next_steps": [],
            "dead_end": True,
        }

    prompt = load_prompt(
        "reasoner_evaluate",
        phase=node.phase,
        tool_used=node.tool_used,
        command_run=node.command_run,
        findings_json=json.dumps(findings, indent=2),
    )

    try:
        result = llm.query_local_json(prompt, system=load_prompt("reasoner_system"))
        if isinstance(result, dict):
            logger.info(
                "Reasoning complete: significance=%s, %d next steps, escalate=%s",
                result.get("significance", "?"),
                len(result.get("next_steps", [])),
                result.get("escalate_to_paid", False),
            )
            return result
    except Exception as e:
        logger.warning("Reasoning failed: %s", e)

    # Fallback: conservative assessment
    return {
        "significance": "medium",
        "reasoning": "Reasoning failed, defaulting to medium significance.",
        "escalate_to_paid": False,
        "next_steps": [],
        "dead_end": False,
    }


def generate_next_nodes(
    llm: LLMClient,
    parent_node: PentestNode,
    reasoning: dict,
    target_ip: str,
) -> list[PentestNode]:
    """
    Generate child PTT nodes from reasoning output.

    Converts the reasoner's `next_steps` into concrete PentestNode
    objects that the ReAct loop can execute.

    Args:
        llm: LLMClient instance.
        parent_node: The node whose findings we're expanding from.
        reasoning: Output from reason_about_findings().
        target_ip: Target IP for command generation.

    Returns:
        List of new PentestNode objects (status=pending).
    """
    next_steps = reasoning.get("next_steps", [])
    if not next_steps:
        return []

    nodes = []
    for step in next_steps[:5]:  # Cap at 5 child nodes to prevent explosion
        tool = step.get("tool", "nmap")
        action = step.get("action", "")
        phase = step.get("phase", "enum")

        # Generate the actual command using local LLM
        cmd_prompt = load_prompt("reasoner_command", tool=tool, action=action, target_ip=target_ip)

        try:
            command = llm.query_local(cmd_prompt).strip()
            # Clean up — remove any quotes or markdown
            command = command.strip("`'\"")
        except Exception:
            command = f"{tool} {target_ip}"

        node = PentestNode(
            phase=phase,
            status="pending",
            parent_id=parent_node.id,
            tool_used=tool,
            command_run=command,
            notes=action,
        )
        nodes.append(node)

    logger.info("Generated %d child nodes from reasoning", len(nodes))
    return nodes
