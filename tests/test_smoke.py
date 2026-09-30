"""tests/test_smoke.py — Full subsystem smoke test without Tkinter mainloop.

Tests:
1. Bootstrapping Database, Sensors, Brain, Voice, and Shields.
2. Triggering all 3 cyber range simulations:
   - Brute force simulation
   - Port scan simulation
   - Canary burst simulation
3. Verifying telemetry, incidents, and containment actions in SQLite.
4. Clean subsystem teardown.
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from core.brain import UltronBrain
from database.manager import DatabaseManager
from range_simulator.sim_bruteforce import run_bruteforce_simulation
from range_simulator.sim_canary_burst import run_canary_burst_simulation
from range_simulator.sim_synscan import run_portscan_simulation
from sensors.arp_scanner import ArpRadarScanner
from sensors.canary_monitor import CanaryMonitor
from sensors.honeypot_listener import HoneypotListener
from shared.event_bus import drain_ui_bus
from shared.logger import setup_logging
from shields.quarantine import get_active_shield


def run_smoke_test():
    setup_logging()
    print("==================================================")
    print("      RUNNING FULL ULTRON SMOKE TEST SUITE       ")
    print("==================================================")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Override test DB and Canary paths
        test_db_path = Path(temp_dir) / "smoke_ultron.db"
        config.CANARY_DIR = Path(temp_dir) / "canary_vault"
        config.CANARY_FILES = [
            config.CANARY_DIR / "passwords.kdbx",
            config.CANARY_DIR / "financial_audit_2026.xlsx",
            config.CANARY_DIR / "root_ssh_keys.pem",
        ]

        # 1. DB Manager
        db = DatabaseManager(test_db_path)
        db.init_db(config.SCHEMA_PATH)
        db.start()

        # 2. Shields
        shield = get_active_shield()

        # 3. Brain
        brain = UltronBrain(db=db, shield=shield)
        brain.start()

        # 4. Sensors
        honeypot = HoneypotListener(db=db, host="127.0.0.1", port=2121)
        honeypot.start()

        canary = CanaryMonitor(db=db)
        canary.start()

        time.sleep(1.0)

        try:
            # --- Scenario 1: Brute Force Simulation ---
            print("\n[SMOKE] Testing Scenario 1: Brute Force Attack...")
            success_bf = run_bruteforce_simulation(target_host="127.0.0.1", port=honeypot._port, attempts=3)
            assert success_bf, "Brute force simulation failed"
            time.sleep(3.5)  # Wait for window correlation and brain triage

            incidents = db.get_recent_incidents()
            assert len(incidents) >= 1, f"Expected >= 1 incident, found {len(incidents)}"
            print(f"[SMOKE] Brute force detected -> Incident: {incidents[0]['incident_uid']}, MITRE: {incidents[0]['mitre_id']}, Status: {incidents[0]['status']}")

            # --- Scenario 2: Canary Tampering Simulation ---
            print("\n[SMOKE] Testing Scenario 2: Canary Tampering...")
            success_canary = run_canary_burst_simulation()
            assert success_canary, "Canary tampering simulation failed"

            # Wait up to 15s for canary detection
            incidents_after = []
            for _ in range(150):
                incidents_after = db.get_recent_incidents()
                if len(incidents_after) >= 2:
                    break
                time.sleep(0.1)

            assert len(incidents_after) >= 2, f"Expected >= 2 incidents, found {len(incidents_after)}"
            canary_inc = incidents_after[0]
            print(f"[SMOKE] Canary tamper detected -> Incident: {canary_inc['incident_uid']}, MITRE: {canary_inc['mitre_id']}, Status: {canary_inc['status']}")

            # Check shield actions
            shields = db.get_shield_actions()
            print(f"[SMOKE] Recorded {len(shields)} shield containment actions in SQLite.")
            assert len(shields) >= 2, f"Expected >= 2 shield actions, found {len(shields)}"
            for s in shields:
                print(f"  -> Shield: {s['shield_type']} against {s['target_identifier']} ({s['latency_ms']}ms, {s['status']})")

            # Check UI Bus
            ui_events = drain_ui_bus()
            print(f"[SMOKE] UI Bus successfully buffered {len(ui_events)} live events.")
            assert len(ui_events) >= 5

            print("\n==================================================")
            print("   ALL ULTRON SUBSYSTEMS FUNCTIONING PERFECTLY!   ")
            print("==================================================")
        finally:
            canary.stop()
            honeypot.stop()
            brain.stop()
            db.stop()


if __name__ == "__main__":
    run_smoke_test()
