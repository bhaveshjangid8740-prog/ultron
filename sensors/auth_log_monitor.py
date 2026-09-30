"""sensors/auth_log_monitor.py — Multi-Source Telemetry & Socket Ingestion Engine.

Ingests active network socket connections, listening ports, and authentication
connection events across the local OS to detect unauthorized remote sessions.
Filters out harmless external IPv6/DNS background noise and focuses strictly
on local IPv4 subnets (192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.0.0.1).
"""

import json
import os
import threading
import time
from typing import Dict, List, Optional, Set

import psutil

import config

from database.manager import DatabaseManager
from shared.event_bus import emit_sensor_event, emit_ui_event
from shared.logger import get_logger

logger = get_logger("sensors.auth_log")

# Harmless standard ports to ignore for outbound connections
BENIGN_OUTBOUND_PORTS = {80, 443, 53, 853, 123, 5353, 1900, 5228}

# Suspicious / sensitive service ports that warrant immediate security triage
SUSPICIOUS_SERVICE_PORTS = {21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 4444, 5900, 8080}


def is_local_ipv4(ip: str) -> bool:
    """Returns True only if the IP is an IPv4 address within private/local subnets."""
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 127:
            return True  # Loopback
        if p0 == 10:
            return True  # 10.0.0.0/8
        if p0 == 172 and 16 <= p1 <= 31:
            return True  # 172.16.0.0/12
        if p0 == 192 and p1 == 168:
            return True  # 192.168.0.0/16
    except Exception:
        return False
    return False


class SocketAuthTelemetryMonitor:
    """Monitors live network socket connections and established sessions."""

    def __init__(self, db: DatabaseManager, poll_interval: float = 3.0):
        self._db = db
        self._poll_interval = poll_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_connections: Set[str] = set()

    def start(self) -> None:
        """Starts background socket polling thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop, name="Ultron-SocketMonitor", daemon=True
        )
        self._thread.start()
        logger.info("Socket & Auth telemetry monitor started (IPv4 local subnet filter active).")

    def stop(self) -> None:
        """Stops background monitor."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Socket & Auth telemetry monitor stopped.")

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._inspect_connections()
            except Exception as ex:
                logger.debug("Socket inspection exception: %s", ex)

            for _ in range(int(self._poll_interval * 10)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)

    def _inspect_connections(self) -> None:
        """Scans active TCP/UDP connections for suspicious or unauthorized sockets."""
        try:
            conns = psutil.net_connections(kind="tcp4")
        except Exception:
            return

        for c in conns:
            if c.status == "ESTABLISHED" and c.raddr:
                remote_ip, remote_port = c.raddr.ip, c.raddr.port
                local_port = c.laddr.port if c.laddr else 0

                # 1. Filter out all IPv6 and non-local public IP traffic
                if not is_local_ipv4(remote_ip):
                    continue

                # 2. Filter out standard benign outbound web/DNS ports
                if remote_port in BENIGN_OUTBOUND_PORTS:
                    continue

                # 3. Filter out normal high-port loopback internal IPC
                if remote_ip.startswith("127.") and local_port > 1024 and remote_port > 1024:
                    continue

                # 4. Filter out the SOC agent's own traffic
                if c.pid == os.getpid():
                    continue

                # 5. Filter out local connections already handled by Honeypot (Port 21)
                if local_port == config.HONEYPOT_PORT or remote_port == config.HONEYPOT_PORT:
                    continue

                conn_key = f"{remote_ip}:{remote_port}->{local_port}"
                if conn_key in self._known_connections:
                    continue
                self._known_connections.add(conn_key)

                # Check if this connection is targeting a sensitive service port
                is_suspicious_port = (
                    local_port in SUSPICIOUS_SERVICE_PORTS or remote_port in SUSPICIOUS_SERVICE_PORTS
                )

                # Only emit security incident if genuinely suspicious
                if is_suspicious_port:
                    logger.warning(
                        "SUSPICIOUS LOCAL SOCKET: %s on sensitive port (PID %s)",
                        conn_key, c.pid
                    )

                    payload = {
                        "event": "SUSPICIOUS_SERVICE_SOCKET",
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "pid": c.pid,
                        "status": c.status,
                    }

                    # Enqueue to brain for triage
                    emit_sensor_event({
                        "source_module": "AUTH_LOG",
                        "suspicious_ip": remote_ip,
                        "raw_payload": payload,
                        "target_identifier": remote_ip,
                    })

                    self._db.insert_telemetry_event(
                        source_module="AUTH_LOG",
                        suspicious_ip=remote_ip,
                        raw_payload=json.dumps(payload),
                    )

                # Broadcast live connection to UI
                emit_ui_event({
                    "type": "socket_event",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_port": local_port,
                    "pid": c.pid,
                    "is_suspicious": is_suspicious_port,
                })
