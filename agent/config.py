"""
Configuration loader and validator.

Loads config.yaml with schema validation and sensible defaults.
All other modules import config from here — single source of truth.
"""

import os
import sys
import ipaddress
from pathlib import Path
from typing import Any

import yaml


# ── Required fields that MUST exist in config.yaml ──────────────
REQUIRED_SECTIONS = ["target", "budget", "safety", "llm"]
REQUIRED_TARGET_FIELDS = ["ip", "allowed_ips"]
REQUIRED_BUDGET_FIELDS = ["max_tokens_per_run", "max_api_calls", "max_iterations"]
REQUIRED_SAFETY_FIELDS = ["require_human_approval", "blocked_commands"]


class ConfigError(Exception):
    """Raised when config.yaml is invalid or missing required fields."""
    pass


def _validate_config(cfg: dict) -> None:
    """Validate that all required sections and fields exist."""
    for section in REQUIRED_SECTIONS:
        if section not in cfg:
            raise ConfigError(f"Missing required config section: '{section}'")

    for field in REQUIRED_TARGET_FIELDS:
        if field not in cfg["target"]:
            raise ConfigError(f"Missing required field: target.{field}")

    for field in REQUIRED_BUDGET_FIELDS:
        if field not in cfg["budget"]:
            raise ConfigError(f"Missing required field: budget.{field}")

    for field in REQUIRED_SAFETY_FIELDS:
        if field not in cfg["safety"]:
            raise ConfigError(f"Missing required field: safety.{field}")

    # Validate CIDR notation for allowed_ips
    for cidr in cfg["target"].get("allowed_ips", []):
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise ConfigError(f"Invalid CIDR in allowed_ips: '{cidr}' — {e}")

    # Validate budget values are positive integers
    for field in REQUIRED_BUDGET_FIELDS:
        val = cfg["budget"][field]
        if not isinstance(val, int) or val <= 0:
            raise ConfigError(
                f"budget.{field} must be a positive integer, got: {val}"
            )


def _apply_defaults(cfg: dict) -> dict:
    """Apply sensible defaults for optional fields."""
    cfg["target"].setdefault("allowed_ports", [22, 80, 443, 8080])
    cfg["safety"].setdefault("destructive_keywords", [
        "exploit", "msfconsole", "reverse_tcp", "shell", "meterpreter"
    ])
    cfg["safety"].setdefault("max_subprocess_timeout", 600)
    cfg["llm"].setdefault("local_model", "llama3.1:8b")
    cfg["llm"].setdefault("paid_model", "gemini-2.5-flash")
    cfg["llm"].setdefault("ollama_host", "http://localhost:11434")
    cfg["llm"].setdefault("gemini_api_key_env", "GEMINI_API_KEY")
    cfg.setdefault("rag", {})
    cfg["rag"].setdefault("chroma_path", "./data/chroma")
    cfg["rag"].setdefault("embedding_model", "nomic-embed-text")
    cfg["rag"].setdefault("chunk_size", 500)
    cfg["rag"].setdefault("top_k", 3)
    return cfg


def parse_allowed_networks(cfg: dict) -> list[ipaddress.IPv4Network]:
    """Parse allowed_ips CIDRs into network objects for scope checking."""
    networks = []
    for cidr in cfg["target"]["allowed_ips"]:
        networks.append(ipaddress.ip_network(cidr, strict=False))
    return networks


def load_config(path: str | Path = None) -> dict[str, Any]:
    """
    Load and validate config.yaml.

    Args:
        path: Path to config file. Defaults to project root config.yaml.

    Returns:
        Validated config dict with defaults applied.

    Raises:
        ConfigError: If config is invalid.
        FileNotFoundError: If config file doesn't exist.
    """
    if path is None:
        # Walk up from this file to find project root config.yaml
        path = Path(__file__).parent.parent / "config.yaml"

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    if not isinstance(cfg, dict):
        raise ConfigError("config.yaml must be a YAML mapping (dict)")

    _validate_config(cfg)
    cfg = _apply_defaults(cfg)

    # Parse networks once and cache
    cfg["_parsed_networks"] = parse_allowed_networks(cfg)

    return cfg


def get_gemini_api_key(cfg: dict) -> str:
    """Get Gemini API key from environment variable."""
    env_var = cfg["llm"]["gemini_api_key_env"]
    key = os.environ.get(env_var, "")
    if not key:
        print(
            f"[WARNING] Gemini API key not set. "
            f"Set env var '{env_var}' or paid LLM calls will fail.",
            file=sys.stderr,
        )
    return key
