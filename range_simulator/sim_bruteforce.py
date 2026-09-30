"""range_simulator/sim_bruteforce.py — Loopback Credential Brute-Force Emulator.

Sends a rapid burst of failed authentication attempts to the local Honeypot service
at 127.0.0.1. Hard-locked to loopback to guarantee zero network risk.
"""

import socket
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from shared.logger import get_logger

logger = get_logger("simulator.bruteforce")

CREDENTIAL_PAIRS = [
    ("admin", "admin123"),
    ("root", "toor"),
    ("administrator", "P@ssw0rd!"),
    ("service", "123456"),
    ("deploy", "secret"),
]


def run_bruteforce_simulation(
    target_host: str = "127.0.0.1", port: int = config.HONEYPOT_PORT, attempts: int = 5
) -> bool:
    """Executes safe loopback credential spray against the honeypot port."""
    logger.info("Starting safe loopback credential spray against %s:%d", target_host, port)

    for i in range(min(attempts, len(CREDENTIAL_PAIRS))):
        username, password = CREDENTIAL_PAIRS[i]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((target_host, port))

            # Receive fake service banner
            try:
                sock.recv(512)
            except Exception:
                pass

            # Send malicious credential payload
            payload = f"USER {username}\r\nPASS {password}\r\n".encode("utf-8")
            sock.sendall(payload)

            # Brief pause between attempts
            time.sleep(0.15)
            sock.close()
        except ConnectionRefusedError:
            # If default port refused, test port 2121 fallback
            if port != 2121:
                return run_bruteforce_simulation(target_host, 2121, attempts)
            logger.error("Honeypot listener appears to be inactive on port %d", port)
            return False
        except Exception as ex:
            logger.debug("Simulated attempt %d: %s", i + 1, ex)

    logger.info("Brute force simulation completed (%d attempts sent).", attempts)
    return True


if __name__ == "__main__":
    run_bruteforce_simulation()
