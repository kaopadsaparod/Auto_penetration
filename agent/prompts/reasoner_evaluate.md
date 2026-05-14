Phase: {phase}
Tool used: {tool_used}
Command: {command_run}

Findings:
{findings_json}

Analyze these findings and return a JSON object with:
- "significance": "low"|"medium"|"high"|"critical"
- "reasoning": brief explanation (1-2 sentences)
- "escalate_to_paid": true if we need deeper AI analysis
- "next_steps": list of objects, each with:
    - "tool": tool name to use
    - "action": what to do
    - "phase": recon|enum|exploit|post
    - "priority": 1-5 (1=highest)
- "dead_end": true if this branch has no potential

Output ONLY valid JSON.
