"""
Generic shell command executor.
Sandboxed wrapper with timeout and output capture.
"""
import logging
from agent.tools.base import ToolResult, run_subprocess, sanitize_arg

logger = logging.getLogger(__name__)

# Commands that should NEVER be executed even by the shell tool
ABSOLUTE_BLOCKLIST = {
    "rm", "rmdir", "mkfs", "dd", "format", "shutdown",
    "reboot", "halt", "poweroff", "init",
}


def run_shell(
    command_parts: list[str],
    timeout: int = 120,
    cwd: str = None,
) -> ToolResult:
    """
    Execute an arbitrary command with safety checks.

    Args:
        command_parts: Command as a list of strings (NOT a single string).
        timeout: Max seconds before killing.
        cwd: Working directory.

    Returns:
        ToolResult with stdout and stderr.
    """
    if not command_parts:
        return ToolResult(command="(empty)", error="No command provided")

    # Block absolutely dangerous base commands
    base_cmd = command_parts[0].split("/")[-1].lower()
    if base_cmd in ABSOLUTE_BLOCKLIST:
        logger.error("BLOCKED dangerous command: %s", base_cmd)
        return ToolResult(
            command=" ".join(command_parts),
            error=f"Command '{base_cmd}' is in the absolute blocklist",
        )

    # Sanitize each argument
    sanitized = [command_parts[0]]  # binary path is OK
    for arg in command_parts[1:]:
        try:
            sanitized.append(sanitize_arg(arg))
        except Exception as e:
            logger.warning("Rejected arg '%s': %s", arg, e)
            return ToolResult(
                command=" ".join(command_parts),
                error=f"Dangerous argument rejected: {arg}",
            )

    return run_subprocess(sanitized, timeout=timeout, cwd=cwd)
