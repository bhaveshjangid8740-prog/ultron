"""investigation/case_query.py — Natural Language Case Investigation Querying.

Allows SOC analysts to query historical telemetry, incidents, and containment
actions using free-text queries like:
"Show all failed authentications linked to subnet 192.168.1.0/24 over the last 2 hours"
"""

import re
from typing import Any, Dict, List

from database.manager import DatabaseManager
from shared.logger import get_logger

logger = get_logger("investigation.query")


class CaseQueryEngine:
    """Parses natural language case queries and filters incident/telemetry records."""

    def __init__(self, db: DatabaseManager):
        self._db = db

    def query(self, natural_query: str) -> Dict[str, Any]:
        """Translates natural language questions into filtered incident records."""
        q = natural_query.lower()
        logger.info("Executing natural language case query: '%s'", natural_query)

        # 1. Parse target severity filters
        min_severity = None
        if "critical" in q:
            min_severity = "CRITICAL"
        elif "high" in q:
            min_severity = "HIGH"
        elif "medium" in q:
            min_severity = "MEDIUM"
        elif "low" in q:
            min_severity = "LOW"

        # 2. Parse status filters
        status = None
        if "contained" in q:
            status = "CONTAINED"
        elif "active" in q or "open" in q:
            status = "ACTIVE"
        elif "resolved" in q:
            status = "RESOLVED"

        # 3. Parse IP / Subnet filter
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", natural_query)
        target_ip = ip_match.group(1) if ip_match else None

        # 4. Fetch candidate incidents
        incidents = self._db.query_incidents_by_filter(status=status, min_severity=min_severity, limit=50)

        # In-memory refinement
        filtered = []
        for inc in incidents:
            summary = (inc.get("summary") or "").lower()
            mitre = (inc.get("mitre_tactic") or "").lower()
            
            # Substring / keyword matches
            if "brute" in q and "brute" not in summary and "t1110" not in (inc.get("mitre_id") or "").lower():
                continue
            if "canary" in q and "canary" not in summary:
                continue
            if "scan" in q and "scan" not in summary and "discovery" not in mitre:
                continue
            if target_ip and target_ip not in summary:
                # Check related shield actions
                actions = self._db.get_shield_actions_for_incident(inc["id"])
                if not any(target_ip in a.get("target_identifier", "") for a in actions):
                    continue

            filtered.append(inc)

        return {
            "query": natural_query,
            "match_count": len(filtered),
            "results": filtered,
            "parsed_filters": {
                "severity": min_severity,
                "status": status,
                "target_ip": target_ip,
            },
        }
