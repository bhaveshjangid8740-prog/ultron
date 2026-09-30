"""database/manager.py — Sole owner of all SQLite access for Project Ultron.

Architectural Guarantees:
1. Thread-safe writes via a single dedicated background writer thread.
2. Concurrent non-blocking reads via WAL mode and short-lived reader connections.
3. Synchronous result feedback via one-shot ack queues for methods that require row IDs.
"""

import queue
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from shared.logger import get_logger

logger = get_logger("database.manager")


class DatabaseManager:
    """Thread-safe SQLite access manager utilizing WAL mode and a single writer thread."""

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        # Queue item: (sql, params, ack_queue_or_none)
        self._write_queue: queue.Queue[Tuple[str, tuple, Optional[queue.Queue]]] = queue.Queue()
        self._writer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._initialized = False

    def init_db(self, schema_path: str | Path) -> None:
        """Executes the DDL schema to ensure all tables and indexes exist."""
        schema_path = Path(schema_path)
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found at: {schema_path}")

        schema_sql = schema_path.read_text(encoding="utf-8")
        conn = sqlite3.connect(self._db_path, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.executescript(schema_sql)
            conn.commit()
            self._initialized = True
            logger.info("Database initialized successfully at: %s", self._db_path)
        finally:
            conn.close()

    def start(self) -> None:
        """Starts the dedicated writer background thread."""
        if self._writer_thread and self._writer_thread.is_alive():
            return
        self._stop_event.clear()
        self._writer_thread = threading.Thread(
            target=self._writer_loop, name="Ultron-DBWriter", daemon=True
        )
        self._writer_thread.start()
        logger.info("Database writer thread started.")

    def stop(self, timeout: float = 3.0) -> None:
        """Signals writer thread to stop and waits for pending jobs to finish."""
        self._stop_event.set()
        # Put sentinel to unblock writer queue get
        self._write_queue.put(("", (), None))
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=timeout)
        logger.info("Database writer thread stopped.")

    def _writer_loop(self) -> None:
        """Dedicated writer loop. Sole owner of the SQLite write connection."""
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=15.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA synchronous = NORMAL;")

        while not self._stop_event.is_set():
            try:
                sql, params, ack_q = self._write_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if not sql:
                self._write_queue.task_done()
                continue

            try:
                cursor = conn.cursor()
                cursor.execute(sql, params)
                conn.commit()
                last_id = cursor.lastrowid
                if ack_q is not None:
                    ack_q.put((True, last_id))
            except Exception as ex:
                logger.error("DB write error for SQL '%s': %s", sql, ex)
                conn.rollback()
                if ack_q is not None:
                    ack_q.put((False, ex))
            finally:
                self._write_queue.task_done()

        # Drain any remaining writes on shutdown
        while not self._write_queue.empty():
            try:
                sql, params, ack_q = self._write_queue.get_nowait()
                if sql:
                    cursor = conn.cursor()
                    cursor.execute(sql, params)
                    conn.commit()
                    if ack_q is not None:
                        ack_q.put((True, cursor.lastrowid))
                self._write_queue.task_done()
            except Exception:
                break

        conn.close()

    def _get_read_connection(self) -> sqlite3.Connection:
        """Creates a short-lived read connection configured with Row factory."""
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    # ── Write Operations (Queued) ──────────────────────────────────

    def _enqueue_write(self, sql: str, params: tuple, wait_for_ack: bool = False) -> Any:
        ack_q: Optional[queue.Queue] = queue.Queue(maxsize=1) if wait_for_ack else None
        self._write_queue.put((sql, params, ack_q))
        if wait_for_ack and ack_q is not None:
            success, result = ack_q.get(timeout=5.0)
            if not success:
                raise RuntimeError(f"Database write operation failed: {result}")
            return result
        return None

    def upsert_network_asset(
        self,
        ip_address: str,
        mac_address: str,
        hostname: Optional[str] = None,
        is_authorized: bool = False,
    ) -> None:
        """Inserts a new network asset or updates last_seen/hostname if existing."""
        sql = """
            INSERT INTO network_assets (ip_address, mac_address, hostname, is_authorized, last_seen)
            VALUES (?, ?, ?, ?, STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW'))
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address = excluded.mac_address,
                hostname = COALESCE(excluded.hostname, network_assets.hostname),
                last_seen = STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW');
        """
        self._enqueue_write(sql, (ip_address, mac_address.lower(), hostname, 1 if is_authorized else 0))

    def insert_telemetry_event(
        self,
        source_module: str,
        suspicious_ip: Optional[str],
        raw_payload: str,
    ) -> None:
        """Fire-and-forget write from sensor threads."""
        sql = """
            INSERT INTO telemetry_events (source_module, suspicious_ip, raw_payload, correlated)
            VALUES (?, ?, ?, 0);
        """
        self._enqueue_write(sql, (source_module.upper(), suspicious_ip, raw_payload))

    def mark_events_correlated(self, event_ids: List[int]) -> None:
        """Marks a batch of telemetry events as correlated."""
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        sql = f"UPDATE telemetry_events SET correlated = 1 WHERE id IN ({placeholders});"
        self._enqueue_write(sql, tuple(event_ids))

    def log_incident(
        self,
        incident_uid: str,
        risk_score: int,
        severity: str,
        mitre_tactic: Optional[str],
        mitre_id: Optional[str],
        summary: Optional[str],
        status: str = "ACTIVE",
    ) -> int:
        """Synchronously records an incident and returns the newly generated row ID."""
        sql = """
            INSERT INTO incidents (incident_uid, risk_score, severity, mitre_tactic, mitre_id, summary, status)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        params = (incident_uid, risk_score, severity.upper(), mitre_tactic, mitre_id, summary, status.upper())
        row_id = self._enqueue_write(sql, params, wait_for_ack=True)
        return int(row_id)

    def update_incident_status(self, incident_id: int, status: str) -> None:
        """Updates the status column of an incident (append-only audit principle)."""
        sql = "UPDATE incidents SET status = ? WHERE id = ?;"
        self._enqueue_write(sql, (status.upper(), incident_id))

    def log_shield_action(
        self,
        incident_id: int,
        shield_type: str,
        target_identifier: str,
        latency_ms: Optional[int],
        status: str = "COMPLETED",
    ) -> int:
        """Records a containment action executed by Shields or queued for approval."""
        sql = """
            INSERT INTO shield_actions (incident_id, shield_type, target_identifier, latency_ms, status)
            VALUES (?, ?, ?, ?, ?);
        """
        params = (incident_id, shield_type.upper(), target_identifier, latency_ms, status.upper())
        action_id = self._enqueue_write(sql, params, wait_for_ack=True)
        return int(action_id)

    def complete_pending_shield_action(self, action_id: int, latency_ms: int) -> None:
        """Updates a PENDING shield action to COMPLETED with its execution latency."""
        sql = """
            UPDATE shield_actions
            SET status = 'COMPLETED', latency_ms = ?, executed_at = STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW')
            WHERE id = ?;
        """
        self._enqueue_write(sql, (latency_ms, action_id))

    # ── Read Operations (Concurrent) ───────────────────────────────

    def get_uncorrelated_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetches unprocessed telemetry events for the brain loop."""
        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM telemetry_events WHERE correlated = 0 ORDER BY timestamp ASC LIMIT ?;",
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def get_all_assets(self) -> List[Dict[str, Any]]:
        """Returns all discovered assets for the UI Radar view."""
        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM network_assets ORDER BY last_seen DESC;")
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def get_repeat_offender_count(self, ip_address: str, window_hours: int = 24) -> int:
        """Counts historical suspicious occurrences for a given IP in the past N hours."""
        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT COUNT(*) as count FROM telemetry_events
                WHERE suspicious_ip = ?
                AND timestamp >= datetime('now', '-' || ? || ' hours');
                """,
                (ip_address, window_hours),
            )
            row = cur.fetchone()
            return int(row["count"]) if row else 0
        finally:
            conn.close()

    def get_recent_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent incidents with their latest state."""
        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?;", (limit,))
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def get_shield_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent shield containment actions."""
        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM shield_actions ORDER BY executed_at DESC LIMIT ?;", (limit,))
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def get_shield_actions_for_incident(self, incident_id: int) -> List[Dict[str, Any]]:
        """Returns all shield containment actions tied to an incident."""
        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM shield_actions WHERE incident_id = ? ORDER BY executed_at ASC;",
                (incident_id,),
            )
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def query_incidents_by_filter(
        self,
        status: Optional[str] = None,
        min_severity: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Parameterized search used by the natural-language query interface."""
        clauses = []
        params = []
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if min_severity:
            clauses.append("severity = ?")
            params.append(min_severity.upper())

        where_stmt = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM incidents {where_stmt} ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        conn = self._get_read_connection()
        try:
            cur = conn.cursor()
            cur.execute(sql, tuple(params))
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()
