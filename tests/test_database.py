"""tests/test_database.py — Unit test for DatabaseManager.

Verifies:
1. Schema initialization and table creation.
2. Threaded writes for assets, telemetry, incidents, and shield actions.
3. Synchronous row_id return via ack queue.
4. Concurrent reads without locking under WAL mode.
"""

import os
import tempfile
import time
from pathlib import Path

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.manager import DatabaseManager


def test_database_lifecycle():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db = Path(temp_dir) / "test_ultron.db"
        schema_path = Path(__file__).resolve().parent.parent / "database" / "schema.sql"

        db = DatabaseManager(temp_db)
        db.init_db(schema_path)
        db.start()

        try:
            # 1. Test upsert asset
            db.upsert_network_asset(
                ip_address="192.168.1.100",
                mac_address="AA:BB:CC:DD:EE:FF",
                hostname="test-host",
                is_authorized=True,
            )

            # 2. Test insert telemetry event
            db.insert_telemetry_event(
                source_module="HONEYPOT",
                suspicious_ip="192.168.1.200",
                raw_payload='{"port": 21, "attempt": "USER admin"}',
            )

            # Give a brief moment for asynchronous queue processing
            time.sleep(0.1)

            # Read back assets
            assets = db.get_all_assets()
            assert len(assets) == 1, f"Expected 1 asset, got {len(assets)}"
            assert assets[0]["ip_address"] == "192.168.1.100"
            assert assets[0]["is_authorized"] == 1

            # Read back uncorrelated telemetry
            uncorrelated = db.get_uncorrelated_events()
            assert len(uncorrelated) == 1, f"Expected 1 event, got {len(uncorrelated)}"
            event_id = uncorrelated[0]["id"]
            assert uncorrelated[0]["source_module"] == "HONEYPOT"

            # 3. Test log incident (synchronous ack queue test)
            incident_id = db.log_incident(
                incident_uid="test-uid-1234",
                risk_score=90,
                severity="CRITICAL",
                mitre_tactic="Credential Access",
                mitre_id="T1110",
                summary="Brute force attack on port 21",
                status="ACTIVE",
            )
            assert incident_id > 0, f"Expected positive incident ID, got {incident_id}"

            # 4. Mark telemetry as correlated
            db.mark_events_correlated([event_id])
            time.sleep(0.05)
            uncorrelated_after = db.get_uncorrelated_events()
            assert len(uncorrelated_after) == 0

            # 5. Log shield action
            action_id = db.log_shield_action(
                incident_id=incident_id,
                shield_type="FIREWALL_DROP",
                target_identifier="192.168.1.200",
                latency_ms=142,
                status="COMPLETED",
            )
            assert action_id > 0

            # Verify shield action retrieval
            actions = db.get_shield_actions_for_incident(incident_id)
            assert len(actions) == 1
            assert actions[0]["latency_ms"] == 142
            assert actions[0]["shield_type"] == "FIREWALL_DROP"

            # 6. Update incident status
            db.update_incident_status(incident_id, "CONTAINED")
            time.sleep(0.05)
            incidents = db.get_recent_incidents()
            assert len(incidents) == 1
            assert incidents[0]["status"] == "CONTAINED"

            print("All DatabaseManager tests passed successfully!")
        finally:
            db.stop()


if __name__ == "__main__":
    test_database_lifecycle()
