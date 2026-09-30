"""core/correlator.py — Windowed event correlation engine.

Groups raw telemetry signals originating from the same source IP / PID
within a rolling time window so that multi-packet attacks (e.g. 10 failed logins
in 2 seconds) produce ONE correlated incident rather than 10 duplicate alerts.
"""

import time
from typing import Any, Dict, List, Optional

import config
from core.schemas import CorrelatedBatch
from shared.logger import get_logger

logger = get_logger("core.correlator")


class EventCorrelator:
    """Buffers and correlates incoming telemetry events within a rolling window."""

    def __init__(self, window_seconds: float = config.CORRELATION_WINDOW_SECONDS):
        self._window_seconds = window_seconds
        # key: suspicious_ip or target_identifier -> dict of {first_seen, last_seen, events, modules}
        self._buffers: Dict[str, Dict[str, Any]] = {}

    def add_event(self, event: Dict[str, Any]) -> Optional[CorrelatedBatch]:
        """Ingests an event. If the event is high-urgency (like CANARY) or buffer is ready, flushes immediately."""
        target = event.get("suspicious_ip") or event.get("target_identifier") or "UNKNOWN_TARGET"
        source = event.get("source_module", "UNKNOWN")
        now = time.time()

        # Canary trips demand immediate response without waiting for window
        if source.upper() == "CANARY":
            return CorrelatedBatch(
                suspicious_ip=event.get("suspicious_ip", "127.0.0.1"),
                event_count=1,
                source_modules=[source],
                raw_events=[event.get("raw_payload", {})],
                target_identifier=str(event.get("target_identifier", "UNKNOWN_PID")),
            )

        if target not in self._buffers:
            self._buffers[target] = {
                "first_seen": now,
                "last_seen": now,
                "events": [event],
                "modules": {source},
                "target_identifier": event.get("target_identifier", target),
            }
        else:
            buf = self._buffers[target]
            buf["last_seen"] = now
            buf["events"].append(event)
            buf["modules"].add(source)

        return None

    def flush_expired(self) -> List[CorrelatedBatch]:
        """Flushes and returns batches whose correlation window has expired."""
        now = time.time()
        expired_keys = []
        ready_batches = []

        for target, buf in self._buffers.items():
            if now - buf["first_seen"] >= self._window_seconds:
                expired_keys.append(target)
                raw_payloads = [e.get("raw_payload", {}) for e in buf["events"]]
                ready_batches.append(
                    CorrelatedBatch(
                        suspicious_ip=target,
                        event_count=len(buf["events"]),
                        source_modules=list(buf["modules"]),
                        raw_events=raw_payloads,
                        target_identifier=buf["target_identifier"],
                    )
                )

        for key in expired_keys:
            del self._buffers[key]

        return ready_batches
