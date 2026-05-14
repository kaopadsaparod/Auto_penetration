"""
Tests for tool input validation and nmap XML parsing.
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.tools.base import (
    ValidationError, validate_ip, validate_ports,
    validate_target, validate_url, sanitize_arg, ToolResult,
)
from agent.tools.nmap_tool import parse_nmap_xml


class TestValidateIP:
    def test_valid_ip(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"
        assert validate_ip("10.10.10.100") == "10.10.10.100"

    def test_rejects_injection(self):
        with pytest.raises(ValidationError):
            validate_ip("10.10.10.1; rm -rf /")

    def test_rejects_hostname(self):
        with pytest.raises(ValidationError):
            validate_ip("evil.com")

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_ip("")


class TestValidatePorts:
    def test_single_port(self):
        assert validate_ports("80") == "80"

    def test_port_range(self):
        assert validate_ports("1-1000") == "1-1000"

    def test_port_list(self):
        assert validate_ports("22,80,443") == "22,80,443"

    def test_rejects_invalid(self):
        with pytest.raises(ValidationError):
            validate_ports("abc")

    def test_rejects_out_of_range(self):
        with pytest.raises(ValidationError):
            validate_ports("99999")


class TestValidateTarget:
    def test_accepts_ip(self):
        assert validate_target("10.10.10.1") == "10.10.10.1"

    def test_accepts_hostname(self):
        assert validate_target("target.htb") == "target.htb"

    def test_rejects_shell_chars(self):
        with pytest.raises(ValidationError):
            validate_target("10.10.10.1;whoami")
        with pytest.raises(ValidationError):
            validate_target("$(evil)")


class TestValidateURL:
    def test_valid_http(self):
        assert validate_url("http://10.10.10.1:80") == "http://10.10.10.1:80"

    def test_valid_https(self):
        assert validate_url("https://target.htb/login") == "https://target.htb/login"

    def test_rejects_ftp(self):
        with pytest.raises(ValidationError):
            validate_url("ftp://evil.com")


class TestSanitizeArg:
    def test_clean_arg(self):
        assert sanitize_arg("--threads") == "--threads"

    def test_rejects_semicolon(self):
        with pytest.raises(ValidationError):
            sanitize_arg("test; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValidationError):
            sanitize_arg("test | cat /etc/passwd")


class TestToolResult:
    def test_success(self):
        r = ToolResult(command="nmap", raw="output", return_code=0)
        assert r.success is True

    def test_failure_by_error(self):
        r = ToolResult(command="nmap", error="timeout", return_code=0)
        assert r.success is False

    def test_failure_by_rc(self):
        r = ToolResult(command="nmap", return_code=1)
        assert r.success is False


class TestParseNmapXML:
    SAMPLE_XML = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.10.10.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.6p1"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4.49"/>
          </port>
          <port protocol="tcp" portid="3306">
            <state state="closed"/>
            <service name="mysql"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    def test_parses_open_ports(self):
        results = parse_nmap_xml(self.SAMPLE_XML)
        assert len(results) == 2  # Only open ports
        assert results[0]["port"] == 22
        assert results[0]["service"] == "ssh"
        assert results[0]["version"] == "7.6p1"
        assert results[1]["port"] == 80
        assert results[1]["service"] == "http"
        assert results[1]["product"] == "Apache"

    def test_empty_input(self):
        assert parse_nmap_xml("") == []
        assert parse_nmap_xml(None) == []

    def test_invalid_xml(self):
        assert parse_nmap_xml("not xml at all") == []
