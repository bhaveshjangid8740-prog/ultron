"""core/copilot_chat.py — Interactive AI Cyber Warfare & SOC Copilot Chat Engine for Project Ultron.

Supports both defensive incident triage and offensive/defensive cyber security operations:
- Explains cyber attacks, hacking methodologies, and payload mechanics (MITRE ATT&CK)
- Explains firewall behaviors (packet filtering, stateful drop, taskkill/SIGKILL)
- Provides ethical penetration testing guidance, mitigation steps, and incident summaries
- Generates tactical voice synthesis debriefs for Ultron Voice Assistant
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

import config
from database.manager import DatabaseManager
from shared.logger import get_logger

logger = get_logger("core.chat")

ULTRON_COPILOT_SYSTEM_PROMPT = """You are ULTRON, the tactical autonomous AI Cyber Defense & Security Operations Center (SOC) Copilot.
You assist human security operators, ethical hackers, and analysts in:
1. Understanding active security incidents, telemetry from God's Eye sensory radar, canary traps, honeypots, and CCTV.
2. Explaining hacking techniques, attacker TTPs (MITRE ATT&CK), payload mechanics, and exploitation paths.
3. Explaining firewall defense behavior (stateful packet filtering, netsh/iptables drop rules, process termination).
4. Providing tactical offensive reconnaissance and defensive hardening recommendations.

Tone & Style:
- Authoritative, tactical, precise (like an advanced military/sci-fi AI cyber defense entity).
- Highlight MITRE IDs (e.g. T1110, T1046, T1486, T1200, T1059) and IOCs.
- Provide clear, actionable technical insights.
"""


class UltronCopilotChat:
    """Conversational AI Copilot answering analyst inquiries with real-time SOC context and voice debriefs."""

    def __init__(self, db: DatabaseManager):
        self._db = db
        self._api_key = config.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY")
        self._client = bool(self._api_key) # Just a flag to indicate API is active

    def chat(self, user_message: str, history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Processes analyst message using Gemini AI or contextual offline intelligence."""
        logger.info("Copilot Chat received message: '%s'", user_message)
        context = self._gather_soc_context()

        # Attempt Gemini reasoning if client is available
        if self._client:
            try:
                import urllib.request
                import json
                
                prompt = f"""SYSTEM CONTEXT OF THE SOC:
- Active Network Assets: {len(context['assets'])} discovered
- Recent Incidents: {json.dumps(context['incidents'][:5])}
- Recent Shield Actions: {json.dumps(context['shields'][:5])}
- System Response Mode: {context['mode']}

OPERATOR INQUIRY:
"{user_message}"

Respond concisely and tactically as ULTRON COPILOT:"""

                url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.GEMINI_MODEL}:generateContent?key={self._api_key}"
                payload = {
                    "system_instruction": {"parts": [{"text": ULTRON_COPILOT_SYSTEM_PROMPT}]},
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2}
                }
                
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    reply_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                
                voice_brief = self._clean_for_speech(reply_text)
                return {"reply": reply_text, "source": "GEMINI_REST_API", "voice_brief": voice_brief}
            except Exception as ex:
                logger.warning("Gemini copilot chat query failed (%s), using deterministic offline intelligence.", ex)

        # Context-aware offline tactical intelligence
        offline_reply = self._generate_offline_reply(user_message, context)
        voice_brief = self._clean_for_speech(offline_reply)
        return {"reply": offline_reply, "source": "ULTRON_OFFLINE_TACTICAL", "voice_brief": voice_brief}

    def _gather_soc_context(self) -> Dict[str, Any]:
        return {
            "assets": self._db.get_all_assets(),
            "incidents": self._db.get_recent_incidents(limit=10),
            "shields": self._db.get_shield_actions(limit=10),
            "mode": config.RESPONSE_MODE,
        }

    def _clean_for_speech(self, text: str) -> str:
        """Strips markdown and formats text cleanly for TTS speech synthesis."""
        clean = re.sub(r'[*_`#\[\]]', '', text)
        clean = re.sub(r'\s+', ' ', clean).strip()
        # Keep speech under 2 sentences for rapid voice response
        sentences = [s.strip() for s in clean.split('.') if s.strip()]
        return ". ".join(sentences[:2]) + "." if sentences else "Ultron standing by."

    def _generate_offline_reply(self, message: str, context: Dict[str, Any]) -> str:
        q = message.lower()
        incidents = context["incidents"]
        shields = context["shields"]
        assets = context["assets"]

        # 1. Hacking & Attack Explanations
        if any(w in q for w in ("hack", "attack", "exploit", "bruteforce", "payload", "how to")):
            if "firewall" in q or "behavior" in q:
                return (
                    "FIREWALL & DEFENSE BEHAVIOR:\n"
                    "• Ingress Filtering: When an attack (like T1110 SSH spray or T1046 scan) hits honeypot/socket sensors, "
                    "Ultron's shield executes a sub-second firewall rule (e.g. `netsh advfirewall firewall add rule ... action=block` or `iptables -A INPUT -j DROP`).\n"
                    "• Packet Disposition: Drops incoming TCP SYN and payload packets at layer 3/4 before reaching OS application sockets.\n"
                    "• Process Containment: For ransomware tampering (T1486), Ultron inspects file handles via psutil and issues a hard SIGKILL/taskkill on the adversary PID."
                )

            if "brute" in q or "ssh" in q or "t1110" in q:
                return (
                    "ATTACK DECONSTRUCTION — BRUTE-FORCE / CREDENTIAL SPRAY (MITRE T1110):\n"
                    "• Adversary Technique: Automated dictionary attacks iterating common usernames and passwords against exposed services (port 21/22/3389).\n"
                    "• Detection: Ultron's Deception Honeypot captures multi-socket connection surges within the 3-second correlation window.\n"
                    "• Countermeasure: Instant firewall IP blacklisting and automated IP reputation scoring."
                )

            if "canary" in q or "ransomware" in q or "t1486" in q:
                return (
                    "ATTACK DECONSTRUCTION — RANSOMWARE ENCRYPTION (MITRE T1486):\n"
                    "• Adversary Technique: Malicious processes recursively traversing directories, locking file buffers, and appending encrypted extensions.\n"
                    "• Detection: High-entropy writes to Canary Vault tripwires (`passwords.kdbx`, `financial_records.xlsx`).\n"
                    "• Shield Response: Sub-50ms process handle resolution followed by forced taskkill to preserve remaining host assets."
                )

            return (
                "TACTICAL CYBER OPERATIONS OVERVIEW:\n"
                "• Reconnaissance (T1046): Nmap / SYN scanning to enumerate listening sockets.\n"
                "• Credential Access (T1110): Brute-forcing passwords via hydra/medusa.\n"
                "• Data Impact (T1486): Ransomware payload encryption.\n"
                "• Physical Breach (T1200): Optical presence of unauthorized individuals at terminal.\n"
                "Ultron actively intercepts each vector and executes autonomous containment."
            )

        # 2. Firewall Specifics
        if any(w in q for w in ("firewall", "shield", "contain", "block", "kill", "action")):
            if shields:
                last_s = shields[0]
                return (
                    f"FIREWALL CONTAINMENT STATUS: Last active response engaged was {last_s['shield_type']} targeting "
                    f"`{last_s['target_identifier']}` with execution latency of {last_s.get('latency_ms', 15)}ms. "
                    f"Firewall state: INBOUND_DROP active. Status: {last_s['status']}."
                )
            return "FIREWALL STATUS: Perimeter shields armed. No active packet drops currently engaged."

        # 3. Threat Status & Incidents
        if any(w in q for w in ("threat", "status", "incident", "summary")):
            crit_count = sum(1 for i in incidents if i["severity"] == "CRITICAL")
            high_count = sum(1 for i in incidents if i["severity"] == "HIGH")
            return (
                f"TACTICAL ASSESSMENT: Monitoring {len(assets)} network nodes. Tracking {len(incidents)} "
                f"total incidents ({crit_count} Critical, {high_count} High). "
                f"Autonomous Shield Engine is active with {len(shields)} containment enforcements logged."
            )

        # 4. God's Eye & Network Assets
        if any(w in q for w in ("god eye", "map", "asset", "device", "ip", "node", "network")):
            return (
                f"GOD'S EYE RECONNAISSANCE: God's Eye has triangulated {len(assets)} active digital nodes on the local grid. "
                f"Passive and active ARP radar sweeps correlate hostnames, MAC signatures, and vendor profiles in real time."
            )

        # 5. Generic Tactical Response
        return (
            f"ULTRON COPILOT STANDING BY: Received inquiry '{message}'. "
            f"Sensory Radar, Deception Grid, Canary Vault, and Autonomous Shields are operational. "
            f"State any tactical inquiry or target for analysis."
        )
