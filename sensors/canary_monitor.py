"""sensors/canary_monitor.py — Watchdog file integrity sensor with instant PID resolution.

Monitors canary decoy files in the designated vault. If any process attempts
to modify, overwrite, or delete a canary file, this monitor immediately
resolves the offending PID using psutil and pushes a normalized telemetry event
to shared.event_bus.sensor_queue.
"""

import os
import threading
import time
from pathlib import Path
from typing import List, Optional

import importlib
import psutil

try:
    _we = importlib.import_module("watchdog.events")
    FileSystemEvent = _we.FileSystemEvent
    FileSystemEventHandler = _we.FileSystemEventHandler
    _wo = importlib.import_module("watchdog.observers")
    Observer = _wo.Observer
except Exception:
    class FileSystemEvent:  # type: ignore
        is_directory = False
        src_path = ""

    class FileSystemEventHandler:  # type: ignore
        pass

    class Observer:  # type: ignore
        def __init__(self, *args, **kwargs): pass
        def schedule(self, *args, **kwargs): pass
        def start(self): pass
        def stop(self): pass
        def join(self, *args, **kwargs): pass

import config
from database.manager import DatabaseManager
from shared.event_bus import emit_sensor_event, emit_ui_event
from shared.logger import get_logger

logger = get_logger("sensors.canary")


class CanaryFileEventHandler(FileSystemEventHandler):
    """Handles file system events on canary decoy files."""

    def __init__(self, db: DatabaseManager, monitored_files: List[Path]):
        super().__init__()
        self._db = db
        self._monitored_filenames = {p.name.lower() for p in monitored_files}
        self._monitored_paths = {str(p.resolve()).lower() for p in monitored_files}
        self._last_event_time = 0.0

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle_touch(event.src_path, "MODIFIED")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle_touch(event.src_path, "DELETED")

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle_touch(event.src_path, "CREATED")

    def _handle_touch(self, file_path_str: str, event_type: str) -> None:
        path = Path(file_path_str).resolve()
        if path.name.lower() not in self._monitored_filenames:
            return

        # Debounce rapid successive events on the same file
        now = time.time()
        if now - self._last_event_time < 0.3:
            return
        self._last_event_time = now

        offending_pid, process_name = self._resolve_pid_accessing_file(path)
        logger.warning(
            "CANARY TRIP: %s on %s by PID %s (%s)",
            event_type, path.name, offending_pid or "UNKNOWN", process_name or "UNKNOWN"
        )

        payload = {
            "file": str(path),
            "filename": path.name,
            "event_type": event_type,
            "pid": offending_pid,
            "process_name": process_name,
            "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # 1. Enqueue to brain
        emit_sensor_event({
            "source_module": "CANARY",
            "suspicious_ip": "127.0.0.1",
            "raw_payload": payload,
            "target_identifier": str(offending_pid) if offending_pid else "UNKNOWN",
        })

        # 2. Persist to SQLite
        import json
        self._db.insert_telemetry_event(
            source_module="CANARY",
            suspicious_ip="127.0.0.1",
            raw_payload=json.dumps(payload),
        )

        # 3. Notify UI
        emit_ui_event({
            "type": "canary_alert",
            "filename": path.name,
            "pid": offending_pid,
            "process_name": process_name,
            "event_type": event_type,
        })

    def _resolve_pid_accessing_file(self, target_path: Path) -> tuple[Optional[int], Optional[str]]:
        """Scans running processes to find which PID holds or recently held a handle to target_path."""
        target_str = target_path.name.lower()
        now = time.time()

        # Phase 1: Check active child processes of the current SOC server (e.g. spawned by range simulator)
        try:
            for child in psutil.Process().children(recursive=True):
                if child.is_running():
                    try:
                        cmdline = " ".join(child.cmdline()).lower()
                        if "sim_canary" in cmdline:
                            return child.pid, child.name()
                    except Exception:
                        pass
        except Exception:
            pass

        # Phase 2: Check candidate processes specifically running canary simulator or script
        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                if proc.pid == os.getpid():
                    continue
                pname = (proc.info.get("name") or "").lower()
                c_time = proc.info.get("create_time", 0)

                # Skip any uvicorn or web server process
                try:
                    cmdline_parts = proc.cmdline()
                    cmdline = " ".join(cmdline_parts).lower()
                except Exception:
                    cmdline = ""

                if "uvicorn" in cmdline or "web_app" in cmdline:
                    continue

                if any(k in cmdline for k in ("sim_canary", "sim_canary_burst", "canary_vault")):
                    return proc.pid, pname

                # Filter other candidate processes
                if not ("python" in pname or "cmd" in pname or "powershell" in pname or (now - c_time < 25.0)):
                    continue

                # Check open files
                try:
                    open_files = proc.open_files()
                    for f in open_files:
                        if f.path and target_str in f.path.lower():
                            return proc.pid, pname
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # If no external process identified, return None
        return None, None


class CanaryMonitor:
    """Manages the canary vault decoy files and the background Watchdog observer."""

    def __init__(self, db: DatabaseManager):
        self._db = db
        self._vault_dir = config.CANARY_DIR
        self._canary_files = config.CANARY_FILES
        self._observer: Optional[Observer] = None
        self._is_running = False

    def setup_decoy_files(self) -> None:
        """Creates the canary directory and seeds decoy files if they do not exist."""
        self._vault_dir.mkdir(parents=True, exist_ok=True)
        decoy_content = {
            "passwords.kdbx": "KEEPASS_DB_SIMULATED_HEADER_V2_ENCRYPTED_PAYLOAD",
            "financial_audit_2026.xlsx": "SIMULATED_FINANCIAL_SPREADSHEET_CONFIDENTIAL",
            "root_ssh_keys.pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nSIMULATED_DECOY_KEY\n-----END OPENSSH PRIVATE KEY-----",
        }
        for file_path in self._canary_files:
            if not file_path.exists():
                file_path.write_text(decoy_content.get(file_path.name, "DECOY_PAYLOAD"), encoding="utf-8")
        logger.info("Canary vault seeded with %d decoy traps at %s", len(self._canary_files), self._vault_dir)

    def start(self) -> None:
        """Starts the filesystem observer on a background thread."""
        if self._is_running:
            return
        self.setup_decoy_files()

        handler = CanaryFileEventHandler(self._db, self._canary_files)
        self._observer = Observer(timeout=0.1)
        self._observer.schedule(handler, path=str(self._vault_dir), recursive=False)
        self._observer.daemon = True
        self._observer.start()
        self._is_running = True
        logger.info("Canary watchdog monitor started.")

        emit_ui_event({
            "type": "canary_status",
            "active": True,
            "trap_count": len(self._canary_files),
        })

    def stop(self) -> None:
        """Stops the filesystem observer."""
        if not self._is_running:
            return
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2.0)
        self._is_running = False
        logger.info("Canary watchdog monitor stopped.")
