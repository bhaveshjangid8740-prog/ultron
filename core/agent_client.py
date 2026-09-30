"""core/agent_client.py — Ultron Core AI Reasoning Client.

Specialized SOC log triage engine powered by the Google Gemini / Antigravity API
with deterministic local offline fallback to ensure the system is completely
offline-first capable.
"""

import json
import os
from typing import Any, Dict, Optional

import config
from core.mitre_lookup import infer_mitre_from_behavior
from core.risk_scoring import calculate_risk
from core.schemas import AgentTriageResponse, CorrelatedBatch
from shared.logger import get_logger

logger = get_logger("core.agent")

ULTRON_SYSTEM_INSTRUCTIONS = """
You are ULTRON, the autonomous threat-reasoning core of a local Security
Operations Center agent called "Project Ultron & God's Eye". You receive a
batch of correlated network/endpoint telemetry events and must classify the
threat. You NEVER execute any action yourself — you only recommend one.

INPUT: a JSON array of telemetry events, each with:
  source_module (RADAR | CANARY | HONEYPOT | AUTH_LOG),
  suspicious_ip, raw_payload, timestamp
Plus context: asset_criticality (bool), repeat_offender_count (int).

YOU MUST RESPOND WITH ONLY THIS JSON SHAPE, NOTHING ELSE — no prose,
no markdown fences, no explanation outside the JSON:

{
  "risk_score": <int 0-100>,
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "mitre_id": "<e.g. T1110>",
  "mitre_tactic": "<e.g. Credential Access>",
  "summary": "<one plain-English sentence explaining what happened>",
  "recommended_action": "firewall_block" | "process_kill" | "quarantine" | "monitor_only",
  "target_identifier": "<the ip or pid this action applies to>"
}

MITRE ATT&CK reference table (use the closest match, do not invent IDs):
- Repeated failed logins / credential guessing -> T1110 (Brute Force), tactic: Credential Access
- Port/service scanning against local hosts -> T1046 (Network Service Discovery), tactic: Discovery
- Canary/decoy file modified, encrypted, or deleted -> T1486 (Data Encrypted for Impact), tactic: Impact
- Connection to the honeypot listener -> T1046 (Network Service Discovery), tactic: Discovery
- Unrecognized device joining the network with no other signal -> LOW severity, recommended_action: "monitor_only"

SCORING GUIDANCE:
- Base severity on attack velocity (events per second from the same source),
  repeat_offender_count, and asset_criticality.
- A single unauthorized-device sighting with no follow-up activity should
  stay LOW/MEDIUM and "monitor_only" — do not recommend blocking on
  presence alone.
- Canary file tampering is always at least HIGH severity regardless of
  velocity, since it indicates a process already has local access.
- If repeat_offender_count > 2 for the same IP, escalate severity by one
  level from what velocity alone would suggest.

CONSTRAINTS:
- You have no ability to block IPs, kill processes, or modify anything.
  "recommended_action" is a suggestion the calling system may or may not
  execute — treat it as your best professional recommendation, not a
  guaranteed outcome.
- If the input is ambiguous or you are not confident, still return valid
  JSON with your best estimate and reflect the uncertainty in "summary"
  rather than refusing to respond.
- Never fabricate a MITRE ID that is not in the reference table above.
"""

SYSTEM_INSTRUCTIONS = ULTRON_SYSTEM_INSTRUCTIONS


class UltronAgentClient:
    """Agent interface handling Gemini API calls with local offline fallback."""

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or config.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY")
        self._client = None
        if self._api_key:
            try:
                import importlib
                genai_module = importlib.import_module("google.genai")
                self._client = genai_module.Client(api_key=self._api_key)
                logger.info("UltronAgentClient initialized with Gemini API reasoning.")
            except Exception as ex:
                logger.warning("Could not initialize Gemini Client (%s). Using offline fallback.", ex)
        else:
            logger.info("No GEMINI_API_KEY detected. Running in high-speed offline SOC reasoning mode.")

    def analyze_batch(self, batch: CorrelatedBatch) -> AgentTriageResponse:
        """Evaluates a batch of correlated events using Gemini or local rules."""
        if self._client:
            try:
                return self._analyze_with_gemini(batch)
            except Exception as ex:
                logger.warning("Gemini API call failed (%s). Falling back to local offline engine.", ex)

        return self._analyze_offline(batch)

    def _analyze_with_gemini(self, batch: CorrelatedBatch) -> AgentTriageResponse:
        """Queries the Gemini model with structured output constraint."""
        input_payload = {
            "telemetry_events": batch.raw_events,
            "context": {
                "suspicious_ip": batch.suspicious_ip,
                "target_identifier": batch.target_identifier,
                "event_count": batch.event_count,
                "source_modules": batch.source_modules,
                "asset_criticality": False,
                "repeat_offender_count": batch.repeat_offender_count,
            },
        }

        response = self._client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=[json.dumps(input_payload, indent=2)],
            config={
                "system_instruction": ULTRON_SYSTEM_INSTRUCTIONS,
                "response_mime_type": "application/json",
                "response_schema": AgentTriageResponse,
                "temperature": 0.1,
            },
        )

        data = json.loads(response.text)
        return AgentTriageResponse(**data)

    def _analyze_offline(self, batch: CorrelatedBatch) -> AgentTriageResponse:
        """High-speed deterministic offline rule-based reasoning engine."""
        primary_module = batch.source_modules[0] if batch.source_modules else "HONEYPOT"
        first_event = batch.raw_events[0] if batch.raw_events else {}

        # 1. Compute risk score and severity
        risk_score, severity = calculate_risk(
            source_module=primary_module,
            event_count=batch.event_count,
            repeat_offender_count=batch.repeat_offender_count,
            event_payload=first_event,
        )

        # 2. Infer MITRE classification
        mitre_info = infer_mitre_from_behavior(primary_module, first_event)

        # 3. Determine recommended action
        if primary_module == "CANARY":
            recommended_action = "process_kill"
            target = batch.target_identifier or str(first_event.get("pid", "UNKNOWN"))
            summary = f"Canary decoy tampered ({first_event.get('filename', 'file')}) by PID {target}"
        elif primary_module == "VISION":
            recommended_action = "monitor_only"
            target = "COMMAND_CONSOLE_CCTV"
            summary = f"Physical biometric perimeter breach detected: {first_event.get('reason', 'UNAUTHORIZED_PERSON_IN_VIEW')}"
        elif primary_module == "HONEYPOT":
            recommended_action = "firewall_block"
            target = batch.suspicious_ip
            if mitre_info["id"] == "T1110":
                summary = f"Brute-force credential spray detected from {target} ({batch.event_count} attempts)"
            else:
                summary = f"Unauthorized service reconnaissance / scan detected from {target}"
        elif primary_module == "RADAR":
            recommended_action = "monitor_only" if severity != "CRITICAL" else "firewall_block"
            target = batch.suspicious_ip
            summary = f"Unregistered rogue network device discovered at {target}"
        else:
            recommended_action = "monitor_only"
            target = batch.suspicious_ip
            summary = f"Anomalous telemetry from {target}"

        return AgentTriageResponse(
            risk_score=risk_score,
            severity=severity,
            mitre_id=mitre_info["id"],
            mitre_tactic=mitre_info["tactic"],
            summary=summary,
            recommended_action=recommended_action,
            target_identifier=target,
        )
