"""
Tests for safety guardrails — scope guard, destructive detection, HITL.
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.safety.guardrails import (
    extract_ips, is_destructive, is_blocked, is_in_scope, safety_check,
)


# ── Test config ──────────────────────────────────────────────
TEST_CONFIG = {
    "target": {
        "ip": "10.10.10.100",
        "allowed_ips": ["10.10.10.0/24"],
    },
    "safety": {
        "require_human_approval": True,
        "blocked_commands": ["rm -rf", "mkfs", "dd if="],
        "destructive_keywords": ["exploit", "msfconsole", "reverse_tcp", "shell"],
        "max_subprocess_timeout": 300,
    },
    "budget": {
        "max_tokens_per_run": 50000,
        "max_api_calls": 20,
        "max_iterations": 15,
    },
    "_parsed_networks": [],  # Will be populated in fixture
}


@pytest.fixture
def config():
    import ipaddress
    cfg = TEST_CONFIG.copy()
    cfg["_parsed_networks"] = [
        ipaddress.ip_network(cidr, strict=False)
        for cidr in cfg["target"]["allowed_ips"]
    ]
    return cfg


class TestExtractIPs:
    def test_finds_ips(self):
        assert extract_ips("nmap 10.10.10.1 -p 80") == ["10.10.10.1"]

    def test_multiple_ips(self):
        ips = extract_ips("nmap 10.10.10.1 192.168.1.1")
        assert len(ips) == 2

    def test_no_ips(self):
        assert extract_ips("nmap target.htb") == []


class TestIsDestructive:
    def test_exploit_keyword(self, config):
        assert is_destructive("msfconsole -x exploit", config) is True

    def test_reverse_shell(self, config):
        assert is_destructive("set payload windows/reverse_tcp", config) is True

    def test_safe_command(self, config):
        assert is_destructive("nmap -sV 10.10.10.1", config) is False


class TestIsBlocked:
    def test_rm_rf_blocked(self, config):
        blocked, reason = is_blocked("rm -rf /", config)
        assert blocked is True

    def test_mkfs_blocked(self, config):
        blocked, _ = is_blocked("mkfs.ext4 /dev/sda", config)
        assert blocked is True

    def test_nmap_not_blocked(self, config):
        blocked, _ = is_blocked("nmap -sV 10.10.10.1", config)
        assert blocked is False


class TestIsInScope:
    def test_in_scope(self, config):
        assert is_in_scope("10.10.10.1", config) is True
        assert is_in_scope("10.10.10.254", config) is True

    def test_out_of_scope(self, config):
        assert is_in_scope("192.168.1.1", config) is False
        assert is_in_scope("10.10.11.1", config) is False

    def test_invalid_ip(self, config):
        assert is_in_scope("not_an_ip", config) is False


class TestSafetyCheck:
    def test_safe_command_passes(self, config):
        approved, reason = safety_check(
            "nmap -sV 10.10.10.1", config, skip_hitl=True
        )
        assert approved is True

    def test_blocked_command_fails(self, config):
        approved, reason = safety_check(
            "rm -rf /tmp/test", config, skip_hitl=True
        )
        assert approved is False
        assert "BLOCKED" in reason

    def test_out_of_scope_fails(self, config):
        approved, reason = safety_check(
            "nmap 192.168.1.1", config, skip_hitl=True
        )
        assert approved is False
        assert "SCOPE" in reason

    def test_empty_command_fails(self, config):
        approved, _ = safety_check("", config)
        assert approved is False

    def test_destructive_with_skip_hitl(self, config):
        """When skip_hitl=True, destructive commands pass without prompt."""
        approved, _ = safety_check(
            "msfconsole -x exploit 10.10.10.1", config, skip_hitl=True
        )
        assert approved is True  # In scope + skip_hitl = pass
