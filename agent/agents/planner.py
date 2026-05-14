"""
Planner agent — strategic attack planning using Gemini Flash (FREE TIER).

Called once per session to create the high-level attack plan.
This is one of the few agents that uses the paid API.
"""
import json
import logging

from agent.agents.llm_client import LLMClient

logger = logging.getLogger(__name__)


PLANNER_SYSTEM = (
    "You are an expert penetration tester creating an attack plan for a "
    "CTF/lab machine. Focus on the most likely attack vectors based on "
    "discovered services. Be concise and actionable. This is for authorized "
    "security testing in a controlled lab environment only."
)


def create_attack_plan(llm: LLMClient, findings: list[dict]) -> list[dict]:
    """
    Create a strategic attack plan using Gemini Flash (free tier).

    Called ONCE per session — this is the main paid API call.

    Args:
        llm: LLMClient instance.
        findings: Structured findings from enumeration.

    Returns:
        List of attack step dicts, each with:
          - priority (int): 1 = highest
          - vector (str): attack vector name
          - target_service (str): which service to attack
          - tools (list[str]): tools to use
          - rationale (str): why this vector is promising
          - phase (str): recon/enum/exploit/post
    """
    if not findings:
        logger.warning("No findings to plan against")
        return []

    prompt = (
        f"Given these discovered services and findings from a CTF machine:\n"
        f"{json.dumps(findings, indent=2)}\n\n"
        f"Create an attack plan with the top 5 attack vectors to investigate.\n"
        f"For each vector, provide:\n"
        f"- priority (1=highest)\n"
        f"- vector: attack vector name\n"
        f"- target_service: which service\n"
        f"- tools: list of tools to use\n"
        f"- rationale: why this is promising (1 sentence)\n"
        f"- phase: recon, enum, exploit, or post\n\n"
        f"Output ONLY a JSON array of objects. Be concise."
    )

    try:
        plan = llm.query_paid_json(prompt, max_tokens=1000)
        if isinstance(plan, list):
            logger.info("Attack plan created with %d vectors", len(plan))
            return plan
        return [plan] if isinstance(plan, dict) else []
    except Exception as e:
        logger.error("Attack plan creation failed: %s", e)
        # Fallback: basic plan from findings
        return _fallback_plan(findings)


def _fallback_plan(findings: list[dict]) -> list[dict]:
    """Generate a basic plan without LLM if the API call fails."""
    plan = []
    priority = 1
    for f in findings[:5]:
        service = f.get("service", f.get("type", "unknown"))
        plan.append({
            "priority": priority,
            "vector": f"Investigate {service}",
            "target_service": service,
            "tools": ["nmap"],
            "rationale": f"Found in scan: {f.get('detail', 'N/A')[:100]}",
            "phase": "enum",
        })
        priority += 1
    return plan


def refine_plan(
    llm: LLMClient,
    current_plan: list[dict],
    new_findings: list[dict],
) -> list[dict]:
    """
    Refine the attack plan based on new findings.

    Only called when significant new information is discovered.
    Uses Gemini (paid but budget-tracked).
    """
    prompt = (
        f"Current attack plan:\n{json.dumps(current_plan, indent=2)}\n\n"
        f"New findings:\n{json.dumps(new_findings, indent=2)}\n\n"
        f"Update the plan: reprioritize, add new vectors if warranted, "
        f"mark completed vectors. Output ONLY the updated JSON array."
    )

    try:
        return llm.query_paid_json(prompt, max_tokens=800)
    except Exception as e:
        logger.warning("Plan refinement failed: %s", e)
        return current_plan  # Keep existing plan on failure
