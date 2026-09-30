"""Configuration settings for Project Ultron & God's Eye.

All paths, timing thresholds, response modes, and network ports
are centralized here.
"""

import os
from pathlib import Path
# Load optional .env file without external dependency
_env_file = Path(__file__).resolve().parent / ".env"
if _env_file.exists():
    try:
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip().strip("'\""))
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent

# Database configuration
DB_PATH = BASE_DIR / "ultron.db"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"

# System Operation Mode: 'AUTONOMOUS' | 'HUMAN_APPROVAL'
RESPONSE_MODE = os.getenv("ULTRON_RESPONSE_MODE", "AUTONOMOUS")

# AI & API Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")

# Honeypot Configuration
HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "21"))  # FTP trap

# Canary Decoy Files
CANARY_DIR = BASE_DIR / "canary_vault"
CANARY_FILES = [
    CANARY_DIR / "passwords.kdbx",
    CANARY_DIR / "financial_audit_2026.xlsx",
    CANARY_DIR / "root_ssh_keys.pem",
]

# Sensory Timing & Thresholds
ARP_SCAN_INTERVAL = float(os.getenv("ARP_SCAN_INTERVAL", "10.0"))
CORRELATION_WINDOW_SECONDS = float(os.getenv("CORRELATION_WINDOW", "3.0"))
CONTAINMENT_LATENCY_BUDGET_MS = 500

# UI Settings
UI_POLL_INTERVAL_MS = 100
UI_TITLE = "ULTRON // GOD'S EYE — Autonomous SOC Command Center"
UI_GEOMETRY = "1600x920"

# Risk Scoring Bands
RISK_BANDS = {
    "LOW": (0, 30),
    "MEDIUM": (31, 60),
    "HIGH": (61, 80),
    "CRITICAL": (81, 100),
}
