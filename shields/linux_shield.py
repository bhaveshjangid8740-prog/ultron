"""shields/linux_shield.py — Linux-native active containment implementation."""

import os
import signal
import subprocess
import time

from shields.base import ShieldResult
from shields.privilege_check import is_elevated
from shared.logger import get_logger

logger = get_logger("shields.linux")


class LinuxShield:
    """Active containment executor utilizing iptables and SIGKILL on Linux."""

    def __init__(self):
        self._elevated = is_elevated()
        if not self._elevated:
            logger.warning("LinuxShield running without root privileges. Containment will run in simulated mode.")

    def block_ip(self, ip: str) -> ShieldResult:
        """Appends DROP rule to iptables INPUT chain."""
        t_start = time.perf_counter()
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        success = True
        message = f"iptables DROP rule applied for {ip}"

        if self._elevated:
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2.0)
                if proc.returncode != 0:
                    success = False
                    message = f"iptables error: {proc.stderr.strip()}"
            except Exception as ex:
                success = False
                message = f"iptables invocation failed: {ex}"
        else:
            time.sleep(0.01)
            message = f"[SAFE_MODE] iptables block simulated for {ip}"

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        return ShieldResult(
            success=success,
            shield_type="FIREWALL_DROP",
            target=ip,
            latency_ms=latency_ms,
            message=message,
            os_command=cmd,
        )

    def kill_process(self, pid: any) -> ShieldResult:
        """Sends SIGKILL to target process."""
        if not pid or str(pid).upper().startswith("UNKNOWN") or not str(pid).isdigit():
            logger.warning("LinuxShield.kill_process skipped: PID '%s' is unknown or invalid.", pid)
            return ShieldResult(
                success=False,
                shield_type="PROCESS_KILL",
                target=str(pid),
                latency_ms=0,
                message=f"Process termination skipped: PID '{pid}' is unknown.",
            )

        int_pid = int(pid)
        if int_pid == os.getpid():
            logger.warning("LinuxShield.kill_process skipped: PID %d is the SOC agent itself.", int_pid)
            return ShieldResult(
                success=True,
                shield_type="PROCESS_KILL",
                target=str(int_pid),
                latency_ms=0,
                message=f"[PROTECTED] Cannot terminate self process PID {int_pid}.",
            )

        t_start = time.perf_counter()
        success = True
        message = f"Process PID {int_pid} sent SIGKILL"

        try:
            os.kill(int_pid, signal.SIGKILL)
        except ProcessLookupError:
            message = f"PID {int_pid} not found (already terminated)"
        except PermissionError:
            success = False
            message = f"Permission denied sending SIGKILL to PID {int_pid}"
        except Exception as ex:
            success = False
            message = f"Error killing PID {int_pid}: {ex}"

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        return ShieldResult(
            success=success,
            shield_type="PROCESS_KILL",
            target=str(int_pid),
            latency_ms=latency_ms,
            message=message,
        )

    def quarantine_host(self) -> ShieldResult:
        """Sets default iptables INPUT policy to DROP."""
        t_start = time.perf_counter()
        cmd = "iptables -P INPUT DROP"
        success = True
        message = "Host quarantined via iptables default DROP policy"

        if self._elevated:
            try:
                subprocess.run(cmd, shell=True, capture_output=True, timeout=2.0)
            except Exception as ex:
                success = False
                message = f"Failed to quarantine host: {ex}"
        else:
            time.sleep(0.015)
            message = "[SAFE_MODE] Host quarantine simulated"

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        return ShieldResult(
            success=success,
            shield_type="QUARANTINE",
            target="LOCAL_HOST",
            latency_ms=latency_ms,
            message=message,
            os_command=cmd,
        )
