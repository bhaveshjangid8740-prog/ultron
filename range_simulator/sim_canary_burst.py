"""range_simulator/sim_canary_burst.py — Ransomware / File Tampering Emulator.

Simulates a malicious process modifying sensitive decoy files in the canary vault,
triggering Watchdog file integrity alarms and active PID-based process termination.
Runs in an active loop until terminated by Ultron's Autonomous Shield.
"""

import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from shared.logger import get_logger

logger = get_logger("simulator.canary_burst")


def run_canary_burst_simulation(max_seconds: float = 30.0) -> bool:
    """Simulates an intruder process actively encrypting a decoy trap file until neutralized."""
    current_pid = os.getpid()
    logger.warning("[SIMULATED ATTACKER] Active ransomware encryption simulator running as PID: %d", current_pid)

    target_file = config.CANARY_FILES[0]  # passwords.kdbx
    if not target_file.exists():
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("DECOY_ORIGINAL_DATA", encoding="utf-8")

    start_time = time.time()
    iteration = 0

    try:
        while time.time() - start_time < max_seconds:
            iteration += 1
            # Append encrypted header chunk and flush to trigger directory notification
            with open(target_file, "a", encoding="utf-8") as f:
                f.write(f"\n[ENCRYPTED_BURST_CHUNK_{iteration}_PID_{current_pid}_TS_{time.time()}]")
                f.flush()
            time.sleep(0.4)

        logger.info("Canary attacker completed loop without being terminated.")
        return True
    except Exception as ex:
        logger.info("[ATTACK TERMINATED] Attacker process PID %d was halted: %s", current_pid, ex)
        return False


if __name__ == "__main__":
    run_canary_burst_simulation()
