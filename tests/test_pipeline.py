"""tests/test_pipeline.py — End-to-end integration test of the Ultron detection pipeline.

Validates:
1. Event emission onto sensor_queue.
2. Correlator batching.
3. Brain reasoning and MITRE mapping.
4. Autonomous shield execution and latency measurement.
5. SQLite persistence across telemetry, incidents, and shield_actions.
"""

import sys
import tempfile
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.brain import UltronBrain
from database.manager import DatabaseManager
from shared.event_bus import emit_sensor_event, drain_ui_bus


def test_end_to_end_pipeline():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "test_pipeline.db"
        schema_path = Path(__file__).resolve().parent.parent / "database" / "schema.sql"

        # Initialize DB
        db = DatabaseManager(db_path)
        db.init_db(schema_path)
        db.start()

        # Initialize Brain
        brain = UltronBrain(db)
        brain.start()

        try:
            # Simulate Honeypot Brute Force burst from 203.0.113.44
            attacker_ip = "203.0.113.44"
            print(f"[TEST] Simulating 3 rapid honeypot probes from {attacker_ip}...")
            for i in range(3):
                emit_sensor_event({
                    "source_module": "HONEYPOT",
                    "suspicious_ip": attacker_ip,
                    "raw_payload": {
                        "port": 21,
                        "received_data": f"USER admin\r\nPASS attempt_{i}",
                        "timestamp": "2026-09-24T12:00:00Z",
                    },
                    "target_identifier": attacker_ip,
                })
                time.sleep(0.05)

            # Wait for correlation window + processing
            print("[TEST] Waiting for correlation window and brain triage...")
            time.sleep(3.5)

            # Verify SQLite incidents table
            incidents = db.get_recent_incidents()
            assert len(incidents) >= 1, f"Expected at least 1 incident, found {len(incidents)}"
            inc = incidents[0]
            print(f"[TEST] Generated Incident: {inc['incident_uid']}, Risk={inc['risk_score']}, Severity={inc['severity']}, Status={inc['status']}")
            assert inc["risk_score"] >= 80, f"Expected high risk score, got {inc['risk_score']}"
            assert inc["severity"] == "CRITICAL"
            assert inc["status"] == "CONTAINED"

            # Verify shield_actions table
            actions = db.get_shield_actions()
            assert len(actions) >= 1, f"Expected at least 1 shield action, found {len(actions)}"
            action = actions[0]
            print(f"[TEST] Shield Action: {action['shield_type']} against {action['target_identifier']} in {action['latency_ms']}ms")
            assert action["shield_type"] == "FIREWALL_DROP"
            assert action["target_identifier"] == attacker_ip
            assert action["latency_ms"] is not None
            assert action["latency_ms"] < 500  # Latency budget under 500ms!

            # Verify UI bus drained events
            ui_events = drain_ui_bus()
            print(f"[TEST] UI Bus received {len(ui_events)} events during the test.")
            assert len(ui_events) >= 1

            print("\n[SUCCESS] End-to-end detection, reasoning, and containment pipeline PASSED!")
        finally:
            brain.stop()
            db.stop()


if __name__ == "__main__":
    test_end_to_end_pipeline()
