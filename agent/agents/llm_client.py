"""
Unified LLM client — wraps both Ollama (local/free) and Google Gemini (paid/free-tier).

Key features:
  - extract_json() strips markdown fences from LLM responses (Fix #14)
  - Retry logic with tenacity (Fix #16)
  - Error handling around all LLM calls (Fix #15)
  - Token counting and budget tracking
  - Uses Ollama's `format` param for structured JSON when possible
"""

import json
import logging
import re
import time
import threading
from pathlib import Path
from typing import Any, Optional

from tenacity import (
    retry, stop_after_attempt, wait_exponential,
    retry_if_exception_type, before_sleep_log,
)

logger = logging.getLogger(__name__)

_PROMPT_DIR = Path(__file__).parent.parent / "prompts"

def load_prompt(name: str, **kwargs) -> str:
    """Load a prompt template from agent/prompts/{name}.md and format it."""
    path = _PROMPT_DIR / f"{name}.md"
    template = path.read_text(encoding="utf-8")
    return template.format_map(kwargs) if kwargs else template


# ════════════════════════════════════════════════════════════════
# JSON extraction — Fix #14
# ════════════════════════════════════════════════════════════════

# Pattern to find JSON inside markdown code fences
JSON_FENCE_PATTERN = re.compile(
    r"```(?:json)?\s*\n?(.*?)\n?\s*```",
    re.DOTALL,
)


def extract_json(raw: str) -> Any:
    """
    Extract JSON from LLM response, handling common formatting quirks.

    LLMs often wrap JSON in markdown fences like:
        ```json
        {"key": "value"}
        ```

    This function strips those fences and parses the JSON.

    Args:
        raw: Raw LLM response string.

    Returns:
        Parsed JSON (dict or list).

    Raises:
        json.JSONDecodeError: If no valid JSON can be extracted.
    """
    raw = raw.strip()

    # Try 1: Direct parse (LLM returned clean JSON)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try 2: Extract from markdown code fence
    match = JSON_FENCE_PATTERN.search(raw)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try 3: Find first { or [ and parse from there
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = raw.find(start_char)
        end = raw.rfind(end_char)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(raw[start:end + 1])
            except json.JSONDecodeError:
                pass

    raise json.JSONDecodeError(
        "Could not extract valid JSON from LLM response",
        raw, 0,
    )


# ════════════════════════════════════════════════════════════════
# 429 / Rate-limit exception matching
# ════════════════════════════════════════════════════════════════

def _is_rate_limit_error(exc: BaseException) -> bool:
    """
    Return True for HTTP 429 / rate-limit errors from any Google client.

    Works with both google-genai and google-api-core exception hierarchies.
    Falls back to checking the string representation so we don't need a
    hard import on google.api_core at module level.
    """
    # google.api_core.exceptions.ResourceExhausted (gRPC 429)
    try:
        from google.api_core.exceptions import ResourceExhausted  # type: ignore
        if isinstance(exc, ResourceExhausted):
            return True
    except ImportError:
        pass

    # google.genai.errors.ClientError (REST 429) — confirmed exception type
    try:
        from google.genai.errors import ClientError
        if isinstance(exc, ClientError) and getattr(exc, 'status_code', 0) == 429:
            return True
    except ImportError:
        pass

    # Some SDK versions raise a plain Exception / ClientError with 429 in msg
    msg = str(exc).lower()
    if "429" in msg or "resource exhausted" in msg or "rate limit" in msg:
        return True

    return False


def _retry_on_rate_limit_or_transient(exc: BaseException) -> bool:
    """Tenacity retry predicate: retry on transient + 429 errors."""
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    return _is_rate_limit_error(exc)


# ════════════════════════════════════════════════════════════════
# Soft rate limiter  (proactive guard before hard 429)
# ════════════════════════════════════════════════════════════════

class _RateLimiter:
    """
    Thread-safe sliding-window rate limiter.

    Default: 15 requests per 60 seconds (Gemini free-tier limit).
    Sleeps the caller if issuing the next request would exceed the budget.
    """

    def __init__(self, max_calls: int = 14, period: float = 60.0):
        # Use 14 instead of 15 to leave a 1-call safety margin
        self.max_calls = max_calls
        self.period = period
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            # Purge timestamps outside the sliding window
            self._timestamps = [
                t for t in self._timestamps if now - t < self.period
            ]
            if len(self._timestamps) >= self.max_calls:
                oldest = self._timestamps[0]
                sleep_for = self.period - (now - oldest) + 0.5  # +0.5s buffer
                if sleep_for > 0:
                    logger.info(
                        "Rate limiter: sleeping %.1fs to stay under %d RPM",
                        sleep_for, self.max_calls,
                    )
                    time.sleep(sleep_for)
            self._timestamps.append(time.monotonic())


# Module-level singleton so the limit is shared across LLMClient instances
_gemini_rate_limiter = _RateLimiter()


# ════════════════════════════════════════════════════════════════
# Token tracking
# ════════════════════════════════════════════════════════════════

class TokenTracker:
    """Track token usage across local and paid LLM calls."""

    def __init__(self, max_paid_tokens: int = 50000, max_api_calls: int = 20):
        self.local_tokens = 0
        self.paid_tokens = 0
        self.api_calls = 0
        self.max_paid_tokens = max_paid_tokens
        self.max_api_calls = max_api_calls

    def add_local(self, tokens: int) -> None:
        self.local_tokens += tokens

    def add_paid(self, tokens: int) -> None:
        self.paid_tokens += tokens
        self.api_calls += 1

    @property
    def budget_exhausted(self) -> bool:
        return (self.paid_tokens >= self.max_paid_tokens or
                self.api_calls >= self.max_api_calls)

    def get_summary(self) -> dict:
        return {
            "local_tokens": self.local_tokens,
            "paid_tokens": self.paid_tokens,
            "api_calls": self.api_calls,
            "budget_remaining": self.max_paid_tokens - self.paid_tokens,
            "calls_remaining": self.max_api_calls - self.api_calls,
        }


# ════════════════════════════════════════════════════════════════
# LLM Client
# ════════════════════════════════════════════════════════════════

class LLMClient:
    """
    Unified interface for local (Ollama) and paid (Gemini) LLM calls.

    Usage:
        client = LLMClient(config)
        # Free local call:
        result = client.query_local("Parse this nmap output...")
        # Paid Gemini call (budget-tracked):
        plan = client.query_paid("Create attack plan for...")
        # JSON extraction:
        data = client.query_local_json("Extract ports as JSON...")
    """

    def __init__(self, config: dict):
        self.config = config
        self.tracker = TokenTracker(
            max_paid_tokens=config["budget"]["max_tokens_per_run"],
            max_api_calls=config["budget"]["max_api_calls"],
        )
        self._ollama_client = None
        self._gemini_client = None

    # ── Lazy initialization ──────────────────────────────────

    def _get_ollama(self):
        """Lazy-load Ollama client."""
        if self._ollama_client is None:
            try:
                import ollama
                self._ollama_client = ollama
                logger.info("Ollama client initialized (host: %s)",
                           self.config["llm"].get("ollama_host", "default"))
            except ImportError:
                raise RuntimeError(
                    "ollama package not installed. Run: pip install ollama"
                )
        return self._ollama_client

    def _get_gemini(self):
        """Lazy-load Gemini client."""
        if self._gemini_client is None:
            try:
                from google import genai
                import os
                api_key_env = self.config["llm"].get("gemini_api_key_env", "GEMINI_API_KEY")
                api_key = os.environ.get(api_key_env, "")
                if not api_key:
                    raise RuntimeError(
                        f"Gemini API key not set. Set env var: {api_key_env}"
                    )
                self._gemini_client = genai.Client(api_key=api_key)
                logger.info("Gemini client initialized")
            except ImportError:
                raise RuntimeError(
                    "google-genai package not installed. Run: pip install google-genai"
                )
        return self._gemini_client

    # ── Local LLM (Ollama — FREE) ────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    )
    def query_local(self, prompt: str, system: str = None) -> str:
        """
        Query local Ollama model (FREE).

        Args:
            prompt: User prompt.
            system: Optional system prompt.

        Returns:
            Raw response text.
        """
        client = self._get_ollama()
        model = self.config["llm"]["local_model"]

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = client.chat(model=model, messages=messages)
            content = response["message"]["content"]
            # Estimate tokens (rough: 1 token ≈ 4 chars)
            est_tokens = len(prompt + content) // 4
            self.tracker.add_local(est_tokens)
            logger.debug("Ollama response (%d chars, ~%d tokens)",
                        len(content), est_tokens)
            return content
        except Exception as e:
            logger.error("Ollama query failed: %s", e)
            raise

    def query_local_json(
        self, prompt: str, system: str = None,
        schema: dict = None,
    ) -> Any:
        """
        Query local Ollama and parse response as JSON.

        Uses Ollama's `format` parameter for structured output when
        a schema is provided. Falls back to extract_json() for
        freeform responses.
        """
        client = self._get_ollama()
        model = self.config["llm"]["local_model"]

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            kwargs = {"model": model, "messages": messages}
            if schema:
                kwargs["format"] = schema
            else:
                kwargs["format"] = "json"

            response = client.chat(**kwargs)
            content = response["message"]["content"]
            est_tokens = len(prompt + content) // 4
            self.tracker.add_local(est_tokens)
            return extract_json(content)
        except json.JSONDecodeError:
            logger.warning("JSON parse failed, retrying with explicit prompt")
            retry_prompt = (
                prompt + "\n\nIMPORTANT: Output ONLY valid JSON. "
                "No explanation, no markdown, just the JSON object/array."
            )
            raw = self.query_local(retry_prompt, system)
            return extract_json(raw)
        except Exception as e:
            logger.error("Ollama JSON query failed: %s", e)
            raise

    # ── Paid LLM (Gemini Flash — FREE TIER) ──────────────────

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=120),
        retry=_retry_on_rate_limit_or_transient,
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    def query_paid(self, prompt: str, max_tokens: int = 800) -> str:
        """
        Query Gemini Flash (free tier, budget-tracked).

        Args:
            prompt: User prompt.
            max_tokens: Maximum response tokens.

        Returns:
            Response text.

        Raises:
            RuntimeError: If budget is exhausted.
        """
        if self.tracker.budget_exhausted:
            raise RuntimeError(
                f"Paid API budget exhausted! "
                f"Tokens: {self.tracker.paid_tokens}/{self.tracker.max_paid_tokens}, "
                f"Calls: {self.tracker.api_calls}/{self.tracker.max_api_calls}"
            )

        # ── Soft rate-limit guard ─────────────────────────────
        _gemini_rate_limiter.wait()

        client = self._get_gemini()
        model = self.config["llm"]["paid_model"]

        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config={
                    "max_output_tokens": max_tokens,
                    "temperature": 0.3,  # Low temp for precision
                },
            )
            content = response.text
            # Track usage
            est_tokens = len(prompt + content) // 4
            self.tracker.add_paid(est_tokens)
            logger.info(
                "Gemini response (%d chars, ~%d tokens, call #%d/%d)",
                len(content), est_tokens,
                self.tracker.api_calls, self.tracker.max_api_calls,
            )
            return content
        except Exception as e:
            logger.error("Gemini query failed: %s", e)
            raise

    def query_paid_json(self, prompt: str, max_tokens: int = 800) -> Any:
        """Query Gemini and parse response as JSON."""
        json_prompt = (
            prompt + "\n\nRespond with ONLY valid JSON. "
            "No explanation, no markdown fences, just the JSON."
        )
        raw = self.query_paid(json_prompt, max_tokens)
        return extract_json(raw)
