"""
Reasoner agent — the missing "Reason" step of ReAct (Fix #21).

Evaluates findings BEFORE deciding next actions. Uses local Ollama (FREE).
This is what makes it a true ReAct loop instead of just Act-Parse.
"""
import json
import logging

from agent.agents.llm_client import LLMClient
from agent.ptt import PentestNode

logger = logging.getLogger(__name__)


REASONER_SYSTEM = (
    "You are a penetration testing expert reasoning about scan findings. "
    "Evaluate what was found, what it implies for the target's security, "
    "and what the next logical steps should be. Think step by step. "
    "Consider: Is this a dead end? Is this interesting? Does this open "
    "new attack vectors? Should we escalate to a more thorough scan?"
)


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

    prompt = (
        f"Phase: {node.phase}\n"
        f"Tool used: {node.tool_used}\n"
        f"Command: {node.command_run}\n\n"
        f"Findings:\n{json.dumps(findings, indent=2)}\n\n"
        f"Analyze these findings and return a JSON object with:\n"
        f'- "significance": "low"|"medium"|"high"|"critical"\n'
        f'- "reasoning": brief explanation (1-2 sentences)\n'
        f'- "escalate_to_paid": true if we need deeper AI analysis\n'
        f'- "next_steps": list of objects, each with:\n'
        f'    - "tool": tool name to use\n'
        f'    - "action": what to do\n'
        f'    - "phase": recon|enum|exploit|post\n'
        f'    - "priority": 1-5 (1=highest)\n'
        f'- "dead_end": true if this branch has no potential\n\n'
        f"Output ONLY valid JSON."
    )

    try:
        result = llm.query_local_json(prompt, system=REASONER_SYSTEM)
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
        cmd_prompt = (
            f"Generate the exact CLI command for this pentesting action:\n"
            f"Tool: {tool}\n"
            f"Action: {action}\n"
            f"Target IP: {target_ip}\n\n"
            f"Output ONLY the command string, nothing else."
        )

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
