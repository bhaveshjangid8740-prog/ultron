"""core/mitre_lookup.py — MITRE ATT&CK knowledge base mapping tool.

Exposed to the Ultron Core reasoning agent as a read-only tool to map
observed behavior into formal MITRE tactics and technique IDs.
"""

from typing import Dict, Optional

MITRE_TABLE: Dict[str, Dict[str, str]] = {
    "T1110": {
        "id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential guess on exposed services (e.g. FTP, SSH).",
    },
    "T1046": {
        "id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts via port scanning or sweeps.",
    },
    "T1486": {
        "id": "T1486",
        "technique": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or tamper with sensitive files to interrupt system availability.",
    },
    "T1210": {
        "id": "T1210",
        "technique": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote services to gain unauthorized access across hosts.",
    },
    "T1059": {
        "id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute malicious code.",
    },
    "T1018": {
        "id": "T1018",
        "technique": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may sweep local networks to discover other active systems and MAC addresses.",
    },
    "T1078": {
        "id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access.",
    },
    "T1200": {
        "id": "T1200",
        "technique": "Hardware Additions / Physical Access",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt physical intrusion, unauthorized console access, or visual espionage.",
    },
}


def lookup_mitre(technique_id: str) -> Optional[Dict[str, str]]:
    """Retrieves MITRE metadata for a given technique ID."""
    return MITRE_TABLE.get(technique_id.upper())


def infer_mitre_from_behavior(source_module: str, event_data: dict) -> Dict[str, str]:
    """Offline heuristic inference mapping sensor signals to MITRE techniques."""
    source = source_module.upper()
    if source == "HONEYPOT":
        data_str = str(event_data.get("received_data", "")).upper()
        if "USER" in data_str or "PASS" in data_str or "AUTH" in data_str:
            return MITRE_TABLE["T1110"]
        return MITRE_TABLE["T1046"]

    if source == "CANARY":
        return MITRE_TABLE["T1486"]

    if source == "RADAR":
        return MITRE_TABLE["T1018"]

    if source == "VISION":
        return MITRE_TABLE["T1200"]

    return MITRE_TABLE["T1046"]
