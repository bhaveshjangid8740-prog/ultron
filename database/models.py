"""database/models.py — Typed dataclasses for Ultron DB rows."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class NetworkAsset:
    id: Optional[int]
    ip_address: str
    mac_address: str
    hostname: Optional[str]
    is_authorized: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


@dataclass
class TelemetryEvent:
    id: Optional[int]
    source_module: str  # 'RADAR' | 'CANARY' | 'HONEYPOT' | 'AUTH_LOG'
    suspicious_ip: Optional[str]
    raw_payload: str
    correlated: bool = False
    timestamp: Optional[str] = None


@dataclass
class Incident:
    id: Optional[int]
    incident_uid: str
    risk_score: int
    severity: str       # 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    mitre_tactic: Optional[str]
    mitre_id: Optional[str]
    summary: Optional[str]
    status: str = "ACTIVE"  # 'ACTIVE' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE'
    created_at: Optional[str] = None


@dataclass
class ShieldAction:
    id: Optional[int]
    incident_id: int
    shield_type: str        # 'FIREWALL_DROP' | 'PROCESS_KILL' | 'QUARANTINE'
    target_identifier: str  # IP or PID
    latency_ms: Optional[int]
    status: str = "COMPLETED"  # 'PENDING' | 'COMPLETED' | 'FAILED'
    executed_at: Optional[str] = None
