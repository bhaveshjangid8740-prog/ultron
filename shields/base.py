"""shields/base.py — Abstract strategy interface for OS containment shields."""

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass
class ShieldResult:
    """Result of an executed or attempted containment action."""

    success: bool
    shield_type: str         # 'FIREWALL_DROP' | 'PROCESS_KILL' | 'QUARANTINE'
    target: str              # IP address or PID
    latency_ms: int          # Measured time in ms from invocation to containment
    message: str             # Human-readable result detail
    os_command: Optional[str] = None


class ContainmentShield(Protocol):
    """Protocol implemented by OS-specific containment shields."""

    def block_ip(self, ip: str) -> ShieldResult:
        ...

    def kill_process(self, pid: int) -> ShieldResult:
        ...

    def quarantine_host(self) -> ShieldResult:
        ...
