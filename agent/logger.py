"""
Centralized logging setup.

Call setup_logger() once at startup. All modules then use:
    import logging
    logger = logging.getLogger(__name__)
"""

import logging
import sys
from pathlib import Path


def setup_logger(
    log_dir: str = "./data",
    log_file: str = "agent.log",
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
) -> logging.Logger:
    """
    Configure root logger with dual handlers:
      - Console: INFO level, concise format
      - File: DEBUG level, full timestamps

    Args:
        log_dir:  Directory for log file (created if needed).
        log_file: Log filename.
        console_level: Minimum level for console output.
        file_level: Minimum level for file output.

    Returns:
        Configured root logger.
    """
    # Ensure log directory exists
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture everything, handlers filter

    # Prevent duplicate handlers on repeated calls
    if root_logger.handlers:
        return root_logger

    # ── Console handler ──────────────────────────────────────
    console_fmt = logging.Formatter(
        fmt="%(asctime)s │ %(levelname)-7s │ %(name)-25s │ %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(console_fmt)

    # ── File handler ─────────────────────────────────────────
    file_fmt = logging.Formatter(
        fmt="%(asctime)s │ %(levelname)-7s │ %(name)-30s │ %(funcName)-20s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.FileHandler(
        log_path / log_file, encoding="utf-8", mode="a"
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(file_fmt)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    return root_logger
