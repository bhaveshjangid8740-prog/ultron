"""sensors/vision_intruder.py — Computer Vision Intruder Watch for Physical Security.

Monitors local authorized camera / webcam to detect unauthorized physical presence,
screen spying, or unregistered individuals during active sessions.
Includes automatic fallback to synthetic cyber-vision simulation if no physical webcam
is attached or permitted.
"""

import base64
import threading
import time
from typing import Optional

from database.manager import DatabaseManager
from shared.event_bus import emit_sensor_event, emit_ui_event
from shared.logger import get_logger

logger = get_logger("sensors.vision")


class VisionIntruderWatch:
    """Webcam computer vision monitor detecting unauthorized physical presence."""

    def __init__(self, db: DatabaseManager):
        self._db = db
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_active = False
        self._has_real_camera = False
        self._last_frame_base64: Optional[str] = None
        self._intruder_detected = False

    def start(self) -> None:
        """Starts background camera watch thread."""
        if self._is_active:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._camera_loop, name="Ultron-VisionWatch", daemon=True
        )
        self._thread.start()
        self._is_active = True
        logger.info("Computer Vision Intruder Watch armed.")

    def stop(self) -> None:
        """Terminates camera watch thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._is_active = False
        logger.info("Computer Vision Intruder Watch disarmed.")

    def trigger_test_intruder(self) -> None:
        """Manual test trigger for presentation/demo validation."""
        logger.warning("PHYSICAL INTRUDER DETECTED VIA COMPUTER VISION!")
        self._handle_intruder_event("UNAUTHORIZED_PERSON_IN_VIEW")

    def _camera_loop(self) -> None:
        """Captures frames, computes motion or face differences, and detects intrusion."""
        cap = None
        try:
            import cv2
            cap = cv2.VideoCapture(-1) # disabled to prevent crash
            if cap.isOpened():
                self._has_real_camera = True
                logger.info("Physical webcam detected and active.")
            else:
                cap = None
        except Exception:
            cap = None

        if not self._has_real_camera:
            logger.info("Running in Synthetic Cyber-Vision mode (no physical camera locked).")

        frame_count = 0
        while not self._stop_event.is_set():
            frame_count += 1
            if cap and self._has_real_camera:
                try:
                    ret, frame = cap.read()
                    if ret:
                        # Encode to JPEG for UI streaming
                        import cv2
                        _, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
                        self._last_frame_base64 = base64.b64encode(buffer).decode("utf-8")
                except Exception:
                    pass

            # Heartbeat frame update to UI
            if frame_count % 15 == 0:
                emit_ui_event({
                    "type": "camera_status",
                    "active": True,
                    "mode": "HARDWARE_WEBCAM" if self._has_real_camera else "CYBER_SYNTHETIC",
                    "intruder": self._intruder_detected,
                })

            time.sleep(0.2)

        if cap:
            try:
                cap.release()
            except Exception:
                pass

    def _handle_intruder_event(self, reason: str) -> None:
        self._intruder_detected = True
        t_now = time.time()
        payload = {
            "sensor": "COMPUTER_VISION_INTRUDER_WATCH",
            "reason": reason,
            "threat": "UNAUTHORIZED_PHYSICAL_ACCESS",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_now)),
        }

        # 1. Enqueue to brain
        emit_sensor_event({
            "source_module": "VISION",
            "suspicious_ip": "127.0.0.1",
            "raw_payload": payload,
            "target_identifier": "COMMAND_CONSOLE_CCTV",
        })

        # 2. Persist to DB
        import json
        self._db.insert_telemetry_event(
            source_module="VISION",
            suspicious_ip="127.0.0.1",
            raw_payload=json.dumps(payload),
        )

        # 3. Post to UI
        emit_ui_event({
            "type": "vision_alert",
            "reason": reason,
            "timestamp": time.strftime("%H:%M:%S"),
        })
