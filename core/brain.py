"""core/brain.py — Ultron Cognitive Brain Consumer Loop.

Pulls raw telemetry from shared.event_bus.sensor_queue, correlates events into batches,
queries the reasoning agent (Gemini / Antigravity), persists incidents to SQLite,
and dispatches containment decisions to Autonomous Shields.
"""

import queue
import threading
import time
import uuid
from typing import Optional

import config
from core.agent_client import UltronAgentClient
from core.correlator import EventCorrelator
from core.schemas import AgentTriageResponse, CorrelatedBatch
from database.manager import DatabaseManager
from shared.event_bus import emit_ui_event, sensor_queue
from shared.logger import get_logger
from shields.base import ContainmentShield
from shields.quarantine import get_active_shield

logger = get_logger("core.brain")


class UltronBrain:
    """The central reasoning and containment dispatch engine."""

    def __init__(self, db: DatabaseManager, shield: Optional[ContainmentShield] = None):
        self._db = db
        self._shield = shield or get_active_shield()
        self._agent = UltronAgentClient()
        self._correlator = EventCorrelator(window_seconds=config.CORRELATION_WINDOW_SECONDS)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._response_mode = config.RESPONSE_MODE

    def set_response_mode(self, mode: str) -> None:
        """Toggles between 'AUTONOMOUS' and 'HUMAN_APPROVAL' modes."""
        self._response_mode = mode.upper()
        logger.info("Ultron Brain response mode changed to: %s", self._response_mode)
        emit_ui_event({
            "type": "mode_change",
            "mode": self._response_mode,
        })

    def get_response_mode(self) -> str:
        return self._response_mode

    def start(self) -> None:
        """Starts the brain consumer loop thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._consumer_loop, name="Ultron-BrainLoop", daemon=True
        )
        self._thread.start()
        logger.info("Ultron Brain cognitive loop started.")

    def stop(self) -> None:
        """Stops the consumer loop thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Ultron Brain cognitive loop stopped.")

    def _consumer_loop(self) -> None:
        """Single-threaded event loop to prevent race conditions during correlation."""
        while not self._stop_event.is_set():
            # 1. Dequeue incoming telemetry events
            try:
                event = sensor_queue.get(timeout=0.2)
                ready_batch = self._correlator.add_event(event)
                if ready_batch:
                    self._process_batch(ready_batch)
                sensor_queue.task_done()
            except queue.Empty:
                pass
            except Exception as ex:
                logger.error("Error in brain loop dequeue: %s", ex)

            # 2. Check for expired correlation windows
            try:
                expired_batches = self._correlator.flush_expired()
                for batch in expired_batches:
                    self._process_batch(batch)
            except Exception as ex:
                logger.error("Error flushing expired correlation batches: %s", ex)

    def _process_batch(self, batch: CorrelatedBatch) -> None:
        """Processes a correlated telemetry batch through the AI cognition pipeline."""
        logger.info(
            "Processing incident batch: source=%s, count=%d, target=%s",
            batch.source_modules, batch.event_count, batch.suspicious_ip
        )

        # 1. Fetch repeat offender context
        if batch.suspicious_ip:
            batch.repeat_offender_count = self._db.get_repeat_offender_count(batch.suspicious_ip)

        # 2. Query reasoning agent (Gemini or offline fallback)
        triage: AgentTriageResponse = self._agent.analyze_batch(batch)
        
        if "VISION" in batch.source_modules:
            triage.recommended_action = "monitor_only"

        incident_uid = str(uuid.uuid4())[:8].upper()

        logger.warning(
            "AGENT VERDICT [%s]: score=%d, severity=%s, mitre=%s (%s), action=%s",
            incident_uid, triage.risk_score, triage.severity, triage.mitre_id,
            triage.mitre_tactic, triage.recommended_action
        )

        # 3. Persist incident to SQLite
        incident_id = self._db.log_incident(
            incident_uid=f"INC-{incident_uid}",
            risk_score=triage.risk_score,
            severity=triage.severity,
            mitre_tactic=triage.mitre_tactic,
            mitre_id=triage.mitre_id,
            summary=triage.summary,
            status="ACTIVE",
        )

        # 4. Notify UI Brain Feed
        emit_ui_event({
            "type": "brain_triage",
            "incident_uid": f"INC-{incident_uid}",
            "risk_score": triage.risk_score,
            "severity": triage.severity,
            "mitre_id": triage.mitre_id,
            "mitre_tactic": triage.mitre_tactic,
            "summary": triage.summary,
            "recommended_action": triage.recommended_action,
            "target": triage.target_identifier,
        })

        # 5. Voice alert for critical severity or physical security intrusion
        if "VISION" in batch.source_modules:
            emit_ui_event({
                "type": "vision_alert",
                "reason": triage.summary,
                "timestamp": time.strftime("%H:%M:%S"),
            })
            emit_ui_event({
                "type": "voice_alert",
                "text": "Security Alert. Unauthorized physical presence detected at command station console.",
            })
        elif triage.severity == "CRITICAL":
            emit_ui_event({
                "type": "voice_alert",
                "text": f"Warning. Critical threat detected. Threat classification: {triage.mitre_tactic}. Deploying autonomous shields.",
            })

        # 6. Execute or Queue Containment Shield
        if triage.recommended_action == "monitor_only":
            return

        if self._response_mode == "AUTONOMOUS":
            self.execute_containment(
                incident_id=incident_id,
                action_type=triage.recommended_action,
                target=triage.target_identifier,
            )
        else:
            # HUMAN_APPROVAL mode: record pending action for user approval
            action_id = self._db.log_shield_action(
                incident_id=incident_id,
                shield_type=triage.recommended_action.upper(),
                target_identifier=triage.target_identifier,
                latency_ms=None,
                status="PENDING",
            )
            emit_ui_event({
                "type": "shield_pending",
                "action_id": action_id,
                "incident_id": incident_id,
                "shield_type": triage.recommended_action.upper(),
                "target": triage.target_identifier,
            })

    def execute_containment(self, incident_id: int, action_type: str, target: str) -> None:
        """Executes the OS-level containment shield action and logs timing."""
        result = None
        if action_type in ("firewall_block", "FIREWALL_DROP"):
            result = self._shield.block_ip(target)
        elif action_type in ("process_kill", "PROCESS_KILL"):
            if not target or str(target).upper().startswith("UNKNOWN") or not str(target).isdigit():
                logger.warning("Skipping process_kill: target PID is unknown or invalid (%s)", target)
                return
            try:
                pid = int(target)
                result = self._shield.kill_process(pid)
            except Exception as ex:
                logger.error("Error executing process kill on PID %s: %s", target, ex)
        elif action_type in ("quarantine", "QUARANTINE"):
            result = self._shield.quarantine_host()

        if result:
            # Persist shield execution to DB
            self._db.log_shield_action(
                incident_id=incident_id,
                shield_type=result.shield_type,
                target_identifier=result.target,
                latency_ms=result.latency_ms,
                status="COMPLETED" if result.success else "FAILED",
            )
            # Update incident status to CONTAINED
            self._db.update_incident_status(incident_id, "CONTAINED")

            # Broadcast to UI Shield Log
            emit_ui_event({
                "type": "shield_deployed",
                "shield_type": result.shield_type,
                "target": result.target,
                "latency_ms": result.latency_ms,
                "status": "COMPLETED" if result.success else "FAILED",
                "message": result.message,
            })
