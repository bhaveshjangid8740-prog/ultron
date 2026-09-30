"""sensors/arp_scanner.py — God Eye ARP Radar for local network asset discovery.

Continuously sweeps the local subnet to detect new, authorized, and rogue devices.
Uses Scapy ARP ping where available, with automatic fallback to system ARP cache
parsing ('arp -a') if raw packet injection is unavailable without Npcap/admin rights.
"""

import re
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

import config
from database.manager import DatabaseManager
from shared.event_bus import emit_sensor_event, emit_ui_event
from shared.logger import get_logger

logger = get_logger("sensors.arp")


class ArpRadarScanner:
    """Network asset discovery scanner running periodically on a background thread."""

    def __init__(self, db: DatabaseManager, interval: float = config.ARP_SCAN_INTERVAL):
        self._db = db
        self._interval = interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_assets: Dict[str, Dict] = {}  # mac -> asset info

    def start(self) -> None:
        """Starts the periodic background scan."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._scan_loop, name="Ultron-ArpRadar", daemon=True
        )
        self._thread.start()
        logger.info("ARP Radar scanner thread started.")

    def stop(self) -> None:
        """Signals the scanner loop to terminate."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("ARP Radar scanner thread stopped.")

    def _scan_loop(self) -> None:
        """Runs scan immediately at boot, then repeats every interval seconds."""
        while not self._stop_event.is_set():
            try:
                self.perform_scan()
            except Exception as ex:
                logger.error("Error during ARP scan sweep: %s", ex)
            # Sleep in small increments for responsive shutdown
            for _ in range(int(self._interval * 10)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)

    def perform_scan(self) -> List[Dict[str, Any]]:
        """Executes a single sweep, attempts scapy first then system arp fallback."""
        discovered = self._scan_with_scapy()
        if not discovered:
            discovered = self._scan_with_arp_cache()

        # Seed local host into asset list if not present
        local_ip, local_mac = self._get_local_identity()
        if local_ip:
            discovered.insert(0, {
                "ip": local_ip,
                "mac": local_mac or "00:00:00:00:00:00",
                "hostname": socket.gethostname(),
                "authorized": True,
            })

        for asset in discovered:
            ip = asset["ip"]
            mac = asset["mac"].lower()
            hostname = asset.get("hostname")
            is_authorized = bool(asset.get("authorized", False))

            # Check if this MAC has been seen before
            is_new = mac not in self._known_assets
            self._known_assets[mac] = asset

            # Persist to database
            self._db.upsert_network_asset(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                is_authorized=is_authorized,
            )

            # If brand new unauthorized device detected, emit warning telemetry
            # Do not treat default gateway (.1) or broadcast as rogue
            is_gateway = ip.endswith(".1")
            if is_gateway:
                is_authorized = True
                asset["authorized"] = True

            if is_new and not is_authorized and not ip.startswith("127."):
                logger.warning("ROGUE ASSET DETECTED: IP %s, MAC %s", ip, mac)
                emit_sensor_event({
                    "source_module": "RADAR",
                    "suspicious_ip": ip,
                    "raw_payload": {
                        "event": "NEW_UNAUTHORIZED_MAC",
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                    },
                    "target_identifier": ip,
                })

            # Broadcast to UI Radar panel
            emit_ui_event({
                "type": "asset_update",
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "authorized": is_authorized,
            })

        return discovered

    def _scan_with_scapy(self) -> List[Dict[str, Any]]:
        """Attempts Scapy arping sweep."""
        try:
            import importlib
            scapy_all = importlib.import_module("scapy.all")
            arping = getattr(scapy_all, "arping")
            # Quick subnet probe
            ans, _ = arping("192.168.1.0/24", timeout=1, verbose=False)
            results = []
            for snd, rcv in ans:
                results.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc,
                    "hostname": self._resolve_hostname(rcv.psrc),
                    "authorized": False,
                })
            return results
        except Exception as ex:
            logger.debug("Scapy scan not available or restricted (%s), falling back to system ARP table", ex)
            return []

    def _scan_with_arp_cache(self) -> List[Dict[str, Any]]:
        """Parses local system ARP cache via 'arp -a'."""
        results = []
        try:
            output = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
            # Match IPv4 addresses followed by MAC address (hyphen or colon separated)
            pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17}|[0-9a-fA-F:]{17})\s+(\w+)")
            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip, raw_mac, entry_type = match.groups()
                    # Skip broadcast/multicast addresses
                    if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                        continue
                    mac = raw_mac.replace("-", ":").lower()
                    if mac == "ff:ff:ff:ff:ff:ff":
                        continue
                    results.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": self._resolve_hostname(ip),
                        "authorized": False,
                    })
        except Exception as ex:
            logger.debug("System arp -a parsing failed: %s", ex)
        return results

    def _get_local_identity(self) -> tuple[Optional[str], Optional[str]]:
        """Returns the local machine IP and MAC."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip, "02:00:00:00:00:01"
        except Exception:
            return "127.0.0.1", "00:00:00:00:00:00"

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
