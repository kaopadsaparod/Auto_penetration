"""
Tests for HTML/PDF Dual Report Generation.
"""
import os
import tempfile
import pytest
from unittest.mock import MagicMock
from pathlib import Path

from agent.ptt import PentestNode, PTTStore
from agent.report.generator import generate_report

@pytest.fixture
def test_setup():
    """Set up temporary paths and mock LLM client for testing reports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        html_path = tmpdir_path / "report.html"
        pdf_path = tmpdir_path / "report.pdf"
        
        config = {
            "target": {
                "ip": "10.10.10.100"
            },
            "report": {
                "enabled": True,
                "output_html": str(html_path),
                "output_pdf": str(pdf_path),
                "formats": ["html", "pdf"]
            }
        }
        
        # Initialize an in-memory or temp SQLite PTT database
        db_path = os.path.join(tmpdir, "test_ptt_report.db")
        ptt = PTTStore(db_path=db_path)
        
        # Seed it with a few nodes
        ptt.save(PentestNode(
            phase="recon",
            status="success",
            tool_used="nmap",
            command_run="nmap -sV 10.10.10.100",
            findings=[{"port": 80, "service": "apache", "version": "2.4.49"}]
        ))
        ptt.save(PentestNode(
            phase="exploit",
            status="success",
            tool_used="msf",
            command_run="use exploit/multi/http/apache_normalize_path",
            findings=[{"vuln": "RCE", "severity": "high"}]
        ))
        
        # Mock LLM Client
        llm = MagicMock()
        llm.query_local.return_value = "Mocked executive summary: Apache exploit successful."
        
        yield config, ptt, llm, html_path, pdf_path
        
        ptt.close()

class TestReportGeneration:
    def test_dual_format_report_generation(self, test_setup):
        config, ptt, llm, html_path, pdf_path = test_setup
        
        # Run report generation
        result_path = generate_report(config, ptt, llm)
        
        # Assertions
        assert result_path == str(html_path)
        assert html_path.exists()
        assert pdf_path.exists()
        
        # Check HTML content
        html_content = html_path.read_text(encoding="utf-8")
        assert "10.10.10.100" in html_content
        assert "apache" in html_content
        assert "Mocked executive summary" in html_content
        
        # Verify PDF size is non-zero
        assert pdf_path.stat().st_size > 0
