"""range_simulator/sim_synscan.py — Stealth Port Reconnaissance Emulator.

Sends rapid probe connections across multiple local ports at 127.0.0.1
to simulate network service discovery and port scanning behavior.
"""

import socket
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from shared.logger import get_logger

logger = get_logger("simulator.synscan")

TARGET_PORTS = [21, 22, 80, 443, 8080, 2121]


def run_portscan_simulation(target_host: str = "127.0.0.1") -> bool:
    """Executes safe loopback port probe across standard service ports."""
    logger.info("Executing safe port reconnaissance sweep against %s", target_host)

    open_ports = []
    for port in TARGET_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            res = s.connect_ex((target_host, port))
            if res == 0:
                open_ports.append(port)
                # Send brief discovery probe
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except Exception:
                    pass
            s.close()
            time.sleep(0.05)
        except Exception as ex:
            logger.debug("Port %d probe exception: %s", port, ex)

    logger.info("Port sweep finished. Probed %d ports, open: %s", len(TARGET_PORTS), open_ports)
    return True


if __name__ == "__main__":
    run_portscan_simulation()
