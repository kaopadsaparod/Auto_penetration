"""
HTML Report Generator — creates the final penetration test report.
Uses Jinja2 for templating and local Ollama for the executive summary.
"""
import json
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from agent.agents.llm_client import LLMClient, load_prompt
from agent.ptt import PTTStore

logger = logging.getLogger(__name__)


def generate_executive_summary(
    llm: LLMClient,
    stats: dict,
    attack_plan: list[dict],
    findings_summary: str,
    target_ip: str,
) -> str:
    """Generate a high-level summary using the local LLM (free)."""
    prompt = load_prompt(
        "report_summary",
        target_ip=target_ip,
        total_nodes=stats.get("total_nodes", 0),
        success_count=stats.get("success", 0),
        failed_count=stats.get("failed", 0),
        findings_summary=findings_summary,
        attack_plan=json.dumps(attack_plan, indent=2) if attack_plan else "None",
    )
    
    try:
        # We don't use query_local_json because we want prose text
        summary = llm.query_local(prompt)
        return summary
    except Exception as e:
        logger.error("Failed to generate executive summary: %s", e)
        return "Executive summary generation failed. See detailed findings below."


def extract_findings_summary(nodes: list[dict]) -> str:
    """Condense findings from all nodes into a short string for the LLM."""
    lines = []
    for node in nodes:
        if node.get("status") == "success" and node.get("findings"):
            try:
                # findings is stored as JSON string in the dict export
                findings = json.loads(node["findings"]) if isinstance(node["findings"], str) else node["findings"]
                for f in findings:
                    severity = f.get("severity", f.get("risk_level", "unknown")).upper()
                    detail = f.get("detail", f.get("vector", str(f)))[:100]
                    lines.append(f"[{severity}] {detail}")
            except Exception:
                pass
    return "\n".join(lines[:20])  # Cap at top 20 lines to avoid blowing context


def generate_report(config: dict, ptt: PTTStore, llm: LLMClient) -> str:
    """
    Generate the HTML report and save it to disk.
    
    Args:
        config: Full config dict.
        ptt: Active PTTStore instance.
        llm: Active LLMClient instance.
        
    Returns:
        Path to the generated report.
    """
    report_config = config.get("report", {})
    output_html_path = Path(report_config.get("output_html", report_config.get("output", "data/report.html")))
    output_pdf_path = Path(report_config.get("output_pdf", "data/report.pdf"))
    output_html_path.parent.mkdir(parents=True, exist_ok=True)
    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.info("Generating final report...")
    
    target_ip = config.get("target", {}).get("ip", "Unknown")
    stats = ptt.get_stats()
    nodes = ptt.export_tree()
    
    # Try to load the attack plan if it exists
    attack_plan = []
    try:
        run_summary_file = Path("data/run_summary.json")
        if run_summary_file.exists():
            data = json.loads(run_summary_file.read_text(encoding="utf-8"))
            attack_plan = data.get("attack_plan", [])
    except Exception:
        pass

    findings_summary = extract_findings_summary(nodes)
    
    # Generate the executive summary
    exec_summary = generate_executive_summary(
        llm, stats, attack_plan, findings_summary, target_ip
    )
    
    # Group nodes by phase
    nodes_by_phase = {
        "recon": [], "enum": [], "exploit": [], "post": []
    }
    for n in nodes:
        phase = n.get("phase", "recon")
        if phase in nodes_by_phase:
            nodes_by_phase[phase].append(n)
            
        # Parse JSON fields for the template
        for field in ["findings", "next_hypotheses"]:
            if isinstance(n.get(field), str):
                try:
                    n[field] = json.loads(n[field])
                except Exception:
                    n[field] = []

    # Render template
    env = FileSystemLoader(Path(__file__).parent)
    jinja_env = Environment(loader=env)
    
    try:
        template = jinja_env.get_template("template.html")
        html_content = template.render(
            target_ip=target_ip,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            stats=stats,
            exec_summary=exec_summary,
            attack_plan=attack_plan,
            nodes_by_phase=nodes_by_phase,
            all_nodes=nodes,
        )
        
        output_html_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML Report saved to %s", output_html_path)

        # Check if PDF format is enabled
        formats = report_config.get("formats", ["html", "pdf"])
        if "pdf" in formats:
            try:
                from xhtml2pdf import pisa
                logger.info("Generating PDF report...")
                
                # Resolve CSS variables to static hex values for xhtml2pdf compatibility
                pdf_html = html_content
                css_vars = {
                    "var(--bg)": "#0f172a",
                    "var(--surface)": "#1e293b",
                    "var(--surface-hover)": "#334155",
                    "var(--text)": "#f8fafc",
                    "var(--text-muted)": "#94a3b8",
                    "var(--primary)": "#3b82f6",
                    "var(--success)": "#10b981",
                    "var(--warning)": "#f59e0b",
                    "var(--danger)": "#ef4444",
                    "var(--border)": "#334155",
                }
                for var_name, hex_val in css_vars.items():
                    pdf_html = pdf_html.replace(var_name, hex_val)
                
                with open(output_pdf_path, "wb") as pdf_file:
                    pisa_status = pisa.CreatePDF(pdf_html, dest=pdf_file)
                if pisa_status.err:
                    logger.error("PDF generation failed with %d errors", pisa_status.err)
                else:
                    logger.info("PDF Report saved to %s", output_pdf_path)
            except ImportError:
                logger.warning("xhtml2pdf not installed — skipping PDF report generation")
            except Exception as e:
                logger.error("Failed to generate PDF report: %s", e)

        return str(output_html_path)
        
    except Exception as e:
        logger.error("Template rendering failed: %s", e)
        return ""
