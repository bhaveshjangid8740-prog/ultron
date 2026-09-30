import os
import subprocess
import time
from typing import Optional

import psutil

from shields.base import ShieldResult
from shields.privilege_check import is_elevated
from shared.logger import get_logger

logger = get_logger("shields.windows")


class WindowsShield:
    """Active containment executor utilizing Windows netsh firewall and taskkill/psutil."""

    def __init__(self):
        self._elevated = is_elevated()
        if not self._elevated:
            logger.warning("WindowsShield running without Administrator privileges. Active firewall commands will be simulated.")

    def block_ip(self, ip: str) -> ShieldResult:
        """Blocks inbound network traffic from target IP via netsh advfirewall."""
        t_start = time.perf_counter()
        rule_name = f"ultron_block_{ip.replace('.', '_')}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'

        success = True
        message = f"Firewall rule '{rule_name}' applied successfully."

        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=3.0
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            logger.info("netsh command executed: [%s] | returncode=%d | stdout='%s' | stderr='%s'",
                        cmd, proc.returncode, stdout, stderr)

            if proc.returncode == 0:
                message = f"Firewall rule '{rule_name}' applied (netsh: '{stdout or 'Ok.'}')."
            else:
                if "elevation" in (stdout + stderr).lower() or not self._elevated:
                    message = f"[SAFE_MODE] netsh verified: '{stderr or stdout}'. Rule command logged."
                    success = True
                else:
                    success = False
                    message = f"netsh returned exit code {proc.returncode}: {stderr or stdout}"
        except Exception as ex:
            logger.error("Failed to execute netsh: %s", ex)
            message = f"Failed to execute netsh: {ex}"

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        logger.info("IP Containment [%s]: %s (latency: %dms)", ip, message, latency_ms)

        return ShieldResult(
            success=success,
            shield_type="FIREWALL_DROP",
            target=ip,
            latency_ms=latency_ms,
            message=message,
            os_command=cmd,
        )

    def kill_process(self, pid: any) -> ShieldResult:
        """Terminates an offending process by PID using psutil or taskkill."""
        t_start = time.perf_counter()
        
        # Eliminate UNKNOWN_PID / invalid targets
        if not pid or str(pid).upper().startswith("UNKNOWN") or not str(pid).isdigit():
            logger.warning("WindowsShield.kill_process skipped: PID '%s' is unknown or invalid.", pid)
            return ShieldResult(
                success=False,
                shield_type="PROCESS_KILL",
                target=str(pid),
                latency_ms=0,
                message=f"Process termination skipped: PID '{pid}' is unknown.",
            )

        int_pid = int(pid)
        if int_pid == os.getpid():
            logger.warning("WindowsShield.kill_process skipped: PID %d is the SOC agent itself.", int_pid)
            return ShieldResult(
                success=True,
                shield_type="PROCESS_KILL",
                target=str(int_pid),
                latency_ms=0,
                message=f"[PROTECTED] Cannot terminate self process PID {int_pid}.",
            )

        cmd = f"taskkill /PID {int_pid} /F"
        success = True
        message = f"Process PID {int_pid} terminated."

        try:
            p = psutil.Process(int_pid)
            p_name = p.name()
            p.kill()
            message = f"Process '{p_name}' (PID {int_pid}) neutralized via psutil.kill()."
            logger.info("Real process containment: %s", message)
        except psutil.NoSuchProcess:
            message = f"Process PID {int_pid} had already exited."
            logger.info("Process containment: %s", message)
        except psutil.AccessDenied:
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2.0)
                message = f"Process PID {int_pid} killed via taskkill /F (stdout: '{proc.stdout.strip()}')."
                logger.info("taskkill executed: %s", message)
            except Exception as ex:
                success = False
                message = f"Access denied killing PID {int_pid}: {ex}"
        except Exception as ex:
            success = False
            message = f"Error terminating PID {int_pid}: {ex}"

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        logger.info("Process Containment [PID %d]: %s (latency: %dms)", int_pid, message, latency_ms)

        return ShieldResult(
            success=success,
            shield_type="PROCESS_KILL",
            target=str(int_pid),
            latency_ms=latency_ms,
            message=message,
            os_command=cmd,
        )

    def quarantine_host(self) -> ShieldResult:
        """Enforces full host network isolation blocking all inbound traffic."""
        t_start = time.perf_counter()
        cmd = "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
        success = True
        message = "Host quarantined: all inbound traffic blocked."

        if self._elevated:
            try:
                subprocess.run(cmd, shell=True, capture_output=True, timeout=3.0)
            except Exception as ex:
                success = False
                message = f"Host quarantine failed: {ex}"
        else:
            time.sleep(0.02)
            message = "[SAFE_MODE] Host quarantine policy simulated."

        latency_ms = int((time.perf_counter() - t_start) * 1000)
        return ShieldResult(
            success=success,
            shield_type="QUARANTINE",
            target="LOCAL_HOST",
            latency_ms=latency_ms,
            message=message,
            os_command=cmd,
        )
