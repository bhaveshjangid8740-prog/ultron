"""shared/logger.py — Centralized structured logging for Project Ultron.

Provides consistent formatting across all threads and modules.
"""

import logging
import sys


def setup_logging(level: int = logging.INFO) -> None:
    """Configures root logger with cyberpunk-styled timestamps and clean formatting."""
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%H:%M:%S"

    formatter = logging.Formatter(log_format, date_format)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicate handlers if called multiple times
    if not root.handlers:
        root.addHandler(handler)


def get_logger(subsystem: str) -> logging.Logger:
    """Returns a named logger for a specific subsystem (e.g. 'ultron.sensors.arp')."""
    return logging.getLogger(f"ultron.{subsystem}")
