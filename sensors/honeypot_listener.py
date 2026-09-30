"""sensors/honeypot_listener.py — Deception socket listener for Project Ultron.

Listens on a decoy port (default: 21 FTP) and captures all unauthorized
connection attempts, probes, and brute-force authentication payloads.
"""

import json
import socket
import threading
import time
from typing import Optional

import config
from database.manager import DatabaseManager
from shared.event_bus import emit_sensor_event, emit_ui_event
from shared.logger import get_logger

logger = get_logger("sensors.honeypot")


class HoneypotListener:
    """Multi-threaded decoy listener simulating standard network services (e.g. FTP)."""

    def __init__(self, db: DatabaseManager, host: str = config.HONEYPOT_HOST, port: int = config.HONEYPOT_PORT):
        self._db = db
        self._host = host
        self._port = port
        self._server_socket: Optional[socket.socket] = None
        self._listen_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_active = False

    def start(self) -> None:
        """Binds socket and starts listening thread."""
        if self._is_active:
            return

        self._stop_event.clear()
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self._host, self._port))
            self._server_socket.listen(15)
            self._server_socket.settimeout(1.0)
            self._is_active = True
            logger.info("Honeypot listener armed on %s:%d", self._host, self._port)
        except OSError as ex:
            # If privileged port fails (e.g. non-admin binding port 21), fallback to unprivileged 2121
            fallback_port = 2121
            logger.warning("Failed to bind port %d (%s). Falling back to port %d", self._port, ex, fallback_port)
            self._port = fallback_port
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self._host, self._port))
            self._server_socket.listen(15)
            self._server_socket.settimeout(1.0)
            self._is_active = True
            logger.info("Honeypot listener armed on fallback %s:%d", self._host, self._port)

        self._listen_thread = threading.Thread(
            target=self._accept_loop, name="Ultron-HoneypotListener", daemon=True
        )
        self._listen_thread.start()

        emit_ui_event({
            "type": "honeypot_status",
            "active": True,
            "port": self._port,
        })

    def stop(self) -> None:
        """Closes the server socket and terminates listener thread."""
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._listen_thread and self._listen_thread.is_alive():
            self._listen_thread.join(timeout=2.0)
        self._is_active = False
        logger.info("Honeypot listener deactivated.")

    def _accept_loop(self) -> None:
        """Loop accepting inbound attacker connections."""
        while not self._stop_event.is_set():
            try:
                client_sock, client_addr = self._server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                client_thread.start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as ex:
                if not self._stop_event.is_set():
                    logger.error("Honeypot accept error: %s", ex)
                break

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
        client_ip, client_port = client_addr
        t_detected = time.time()
        logger.warning("HONEYPOT TRIGGERED from %s:%d", client_ip, client_port)

        try:
            client_sock.settimeout(2.0)
            # Send fake service banner
            banner = b"220 ProFTPD 1.3.5 Server ready.\r\n"
            client_sock.sendall(banner)

            # Receive initial command/probe
            try:
                data = client_sock.recv(1024).decode("utf-8", errors="replace").strip()
            except Exception:
                data = "<PROBE_DISCONNECTED>"

            payload = {
                "port": self._port,
                "remote_port": client_port,
                "banner_sent": "ProFTPD 1.3.5",
                "received_data": data,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_detected)),
                "t_detected": t_detected,
            }

            # 1. Enqueue to brain for correlation and LLM analysis
            emit_sensor_event({
                "source_module": "HONEYPOT",
                "suspicious_ip": client_ip,
                "raw_payload": payload,
                "target_identifier": client_ip,
                "t_detected": t_detected,
            })

            # 2. Record raw telemetry in SQLite
            self._db.insert_telemetry_event(
                source_module="HONEYPOT",
                suspicious_ip=client_ip,
                raw_payload=json.dumps(payload),
            )

            # 3. Post to UI
            emit_ui_event({
                "type": "honeypot_hit",
                "ip": client_ip,
                "port": client_port,
                "data": data,
            })

            # Respond with fake auth failure
            try:
                client_sock.sendall(b"530 Login incorrect.\r\n")
            except Exception:
                pass
        except Exception as ex:
            logger.error("Error handling honeypot client %s: %s", client_ip, ex)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
