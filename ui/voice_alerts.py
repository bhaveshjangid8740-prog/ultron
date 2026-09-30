"""ui/voice_alerts.py — Dedicated asynchronous worker thread for pyttsx3 voice alerts."""

import queue
import threading
from typing import Optional

from shared.logger import get_logger

logger = get_logger("ui.voice")


class VoiceAlertWorker:
    """Consumes voice text jobs on a dedicated thread to prevent blocking the GUI or brain loop."""

    def __init__(self):
        self._speech_queue: queue.Queue[str] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._engine = None

    def start(self) -> None:
        """Starts the voice worker thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker_loop, name="Ultron-VoiceWorker", daemon=True
        )
        self._thread.start()
        logger.info("Voice alert worker thread started.")

    def stop(self) -> None:
        """Signals the voice worker thread to exit."""
        self._stop_event.set()
        self._speech_queue.put("")
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Voice alert worker thread stopped.")

    def speak(self, text: str) -> None:
        """Queues a spoken announcement."""
        if text:
            self._speech_queue.put(text)

    def _worker_loop(self) -> None:
        """Initializes TTS engine once on this worker thread and processes announcements."""
        try:
            import pyttsx3
            self._engine = pyttsx3.init()
            self._engine.setProperty("rate", 175)
            # Try to select a clear voice if available
            voices = self._engine.getProperty("voices")
            if voices:
                self._engine.setProperty("voice", voices[0].id)
        except Exception as ex:
            logger.warning("Could not initialize pyttsx3 engine (%s). Voice alerts will be silent.", ex)
            self._engine = None

        while not self._stop_event.is_set():
            try:
                text = self._speech_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if not text or self._stop_event.is_set():
                self._speech_queue.task_done()
                break

            if self._engine:
                try:
                    self._engine.say(text)
                    self._engine.runAndWait()
                except Exception as ex:
                    logger.debug("TTS playback exception: %s", ex)

            self._speech_queue.task_done()
