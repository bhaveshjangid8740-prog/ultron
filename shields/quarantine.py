"""shields/quarantine.py — Shield factory and quarantine coordinator."""

import platform
from shields.base import ContainmentShield
from shields.linux_shield import LinuxShield
from shields.windows_shield import WindowsShield
from shared.logger import get_logger

logger = get_logger("shields.factory")


def get_active_shield() -> ContainmentShield:
    """Strategy pattern factory returning the appropriate OS shield."""
    system = platform.system()
    if system == "Windows":
        logger.info("Instantiating WindowsShield active containment provider.")
        return WindowsShield()
    else:
        logger.info("Instantiating LinuxShield active containment provider.")
        return LinuxShield()
