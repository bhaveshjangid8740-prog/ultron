"""shared/event_bus.py — Thread-safe communication channels for Project Ultron.

Contains two decoupled queue pipelines:
1. sensor_queue: Sensors -> Ultron Brain loop (bounded, drops oldest on overflow to avoid OOM).
2. ui_bus: All subsystems -> CustomTkinter UI poll loop (consumed on main thread).
"""

import queue
import logging
from typing import Any, Dict

logger = logging.getLogger("ultron.event_bus")

# Bounded queue from sensors to cognitive brain
SENSOR_QUEUE_MAXSIZE = 1000
sensor_queue: queue.Queue = queue.Queue(maxsize=SENSOR_QUEUE_MAXSIZE)

# Unbounded queue from all background threads to UI
ui_bus: queue.Queue = queue.Queue()


def emit_sensor_event(event: Dict[str, Any]) -> bool:
    """Safely put a normalized sensor event onto sensor_queue.
    
    If the queue is full, drops the oldest item and puts the new one,
    logging a DoS_SUSPECTED indicator.
    """
    try:
        sensor_queue.put_nowait(event)
        return True
    except queue.Full:
        try:
            dropped = sensor_queue.get_nowait()
            logger.warning("sensor_queue full! Dropped oldest event: %s", dropped.get("source_module", "unknown"))
            # Notify UI of possible DoS / queue saturation
            emit_ui_event({
                "type": "log",
                "severity": "HIGH",
                "message": "WARNING: Telemetry event queue saturated (DoS burst detected). Dropping oldest frames.",
            })
            sensor_queue.put_nowait(event)
            return True
        except (queue.Empty, queue.Full):
            return False


def emit_ui_event(event: Dict[str, Any]) -> None:
    """Post an event onto ui_bus to be rendered safely on the Tkinter main thread."""
    ui_bus.put(event)


def drain_ui_bus() -> list[Dict[str, Any]]:
    """Non-blocking drain of all pending UI events for the current poll tick."""
    events = []
    while True:
        try:
            events.append(ui_bus.get_nowait())
        except queue.Empty:
            break
    return events
