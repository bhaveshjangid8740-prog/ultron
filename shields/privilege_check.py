"""shields/privilege_check.py — Verifies elevated administrative privileges."""

import ctypes
import os
import platform


def is_elevated() -> bool:
    """Checks whether the current process has administrative or root privileges."""
    system = platform.system()
    if system == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        # Linux / Unix
        return os.geteuid() == 0
