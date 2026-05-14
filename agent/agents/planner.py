"""
Planner agent — strategic attack planning using Gemini Flash (FREE TIER).

Called once per session to create the high-level attack plan.
This is one of the few agents that uses the paid API.
"""
import json
import logging

from agent.agents.llm_client import LLMClient, load_prompt

logger = logging.getLogger(__name__)





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

    prompt = load_prompt("planner_system") + "\n\n" + load_prompt(
        "planner_create",
        findings_json=json.dumps(findings, indent=2)
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
    prompt = load_prompt("planner_system") + "\n\n" + load_prompt(
        "planner_refine",
        current_plan_json=json.dumps(current_plan, indent=2),
        new_findings_json=json.dumps(new_findings, indent=2)
    )

    try:
        return llm.query_paid_json(prompt, max_tokens=800)
    except Exception as e:
        logger.warning("Plan refinement failed: %s", e)
        return current_plan  # Keep existing plan on failure
