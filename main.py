"""main.py — Main Application Entrypoint for Project Ultron & God's Eye.

Boot Sequence:
1. Initialize structured logging & config.
2. Initialize and start WAL-mode SQLite DatabaseManager.
3. Instantiate OS-specific containment shields.
4. Start Ultron Cognitive Brain loop.
5. Arm God Eye sensors (Honeypot, Canary Watchdog, ARP Radar).
6. Start asynchronous Voice Alert worker.
7. Launch CustomTkinter Cyberpunk SOC Command Center GUI.
"""

import sys
import threading
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from core.brain import UltronBrain
from database.manager import DatabaseManager
from range_simulator.sim_bruteforce import run_bruteforce_simulation
from range_simulator.sim_canary_burst import run_canary_burst_simulation
from range_simulator.sim_synscan import run_portscan_simulation
from sensors.arp_scanner import ArpRadarScanner
from sensors.canary_monitor import CanaryMonitor
from sensors.honeypot_listener import HoneypotListener
from shared.logger import get_logger, setup_logging
from shields.quarantine import get_active_shield
from ui.main_window import UltronDashboardApp
from ui.voice_alerts import VoiceAlertWorker

logger = get_logger("main")


def main():
    setup_logging()
    logger.info("=====================================================")
    logger.info("      PROJECT ULTRON & GOD'S EYE — BOOTING SOC       ")
    logger.info("=====================================================")

    # 1. Start Database Manager
    db = DatabaseManager(config.DB_PATH)
    db.init_db(config.SCHEMA_PATH)
    db.start()

    # 2. Initialize Shield
    shield = get_active_shield()

    # 3. Start Brain Cognitive Loop
    brain = UltronBrain(db=db, shield=shield)
    brain.start()

    # 4. Start God Eye Sensory Ingestion
    honeypot = HoneypotListener(db=db, host=config.HONEYPOT_HOST, port=config.HONEYPOT_PORT)
    honeypot.start()

    canary = CanaryMonitor(db=db)
    canary.start()

    arp_scanner = ArpRadarScanner(db=db, interval=config.ARP_SCAN_INTERVAL)
    arp_scanner.start()

    # 5. Start Voice Alerts
    voice_worker = VoiceAlertWorker()
    voice_worker.start()

    # 6. Define Simulation Callback
    def on_simulate(scenario: str) -> None:
        logger.info("Cyber Range attack initiated: %s", scenario)
        if scenario == "bruteforce":
            run_bruteforce_simulation(port=honeypot._port)
        elif scenario == "portscan":
            run_portscan_simulation()
        elif scenario == "canary":
            run_canary_burst_simulation()

    # 7. Define Human-Approval Shield Deployment Callback
    def on_approve_shield(action_id: int, incident_id: int, shield_type: str, target: str) -> None:
        logger.info("Human operator approved shield deployment: %s against %s", shield_type, target)
        brain.execute_containment(incident_id=incident_id, action_type=shield_type, target=target)

    # 8. Define Mode Toggle Callback
    def on_toggle_response_mode(mode: str) -> None:
        brain.set_response_mode(mode)

    # 9. Launch Command Center GUI
    app = UltronDashboardApp(
        on_toggle_response_mode=on_toggle_response_mode,
        on_simulate=on_simulate,
        on_approve_shield=on_approve_shield,
        voice_worker=voice_worker,
    )

    # 10. Clean Graceful Shutdown Handler
    def on_close():
        logger.info("Initiating graceful shutdown of all Ultron subsystems...")
        try:
            arp_scanner.stop()
            canary.stop()
            honeypot.stop()
            brain.stop()
            voice_worker.stop()
            db.stop()
        except Exception as ex:
            logger.error("Error during shutdown: %s", ex)
        finally:
            app.destroy()

    app.protocol("WM_DELETE_WINDOW", on_close)

    logger.info("Command Center initialized. Starting main loop.")
    app.mainloop()


if __name__ == "__main__":
    main()
