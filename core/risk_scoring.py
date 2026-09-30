"""core/risk_scoring.py — Heuristic risk scoring engine for Project Ultron.

Calculates risk score (0-100) and severity band based on:
- Base signal severity (Canary trip > Honeypot probe > Rogue MAC)
- Event velocity (rapid bursts from same source IP/PID)
- Historical repeat-offender count from database
"""

from typing import Dict, Tuple


def calculate_risk(
    source_module: str,
    event_count: int,
    repeat_offender_count: int = 0,
    event_payload: Dict = None,
) -> Tuple[int, str]:
    """Calculates risk score (0..100) and severity band.
    
    Returns:
        (risk_score, severity)
    """
    event_payload = event_payload or {}
    source = source_module.upper()

    # 1. Base score by sensor type
    if source == "CANARY":
        base_score = 92  # Direct file tampering is almost always critical
    elif source == "HONEYPOT":
        data_str = str(event_payload.get("received_data", "")).upper()
        if "USER" in data_str or "PASS" in data_str:
            base_score = 82  # Brute force credential attempt
        else:
            base_score = 65  # Port sweep / reconnaissance
    elif source == "RADAR":
        base_score = 35  # Rogue MAC detected on subnet
    elif source == "VISION":
        base_score = 75  # Physical perimeter intruder alert
    else:
        base_score = 40

    # 2. Velocity weight (more events in rolling window = higher confidence)
    velocity_bonus = min(15, (event_count - 1) * 3)

    # 3. Repeat offender weight
    history_bonus = min(20, repeat_offender_count * 5)

    # Final score clamped 0..100
    final_score = min(100, max(0, base_score + velocity_bonus + history_bonus))

    # Severity classification
    if final_score >= 81:
        severity = "CRITICAL"
    elif final_score >= 61:
        severity = "HIGH"
    elif final_score >= 31:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return final_score, severity
