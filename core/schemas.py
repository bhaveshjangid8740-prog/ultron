"""core/schemas.py — Pydantic schemas validating AI cognition contracts."""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class AgentTriageResponse(BaseModel):
    """Structured JSON shape that the Ultron reasoning agent must return."""

    risk_score: int = Field(ge=0, le=100, description="Computed risk score between 0 and 100")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="Severity classification band"
    )
    mitre_id: str = Field(description="MITRE ATT&CK technique ID (e.g. T1110)")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic category (e.g. Credential Access)")
    summary: str = Field(description="Concise plain-English explanation of the incident")
    recommended_action: Literal["firewall_block", "process_kill", "quarantine", "monitor_only"] = Field(
        description="Specific containment action recommended by Ultron"
    )
    target_identifier: str = Field(description="Target IP address or PID to be contained")


class CorrelatedBatch(BaseModel):
    """Context batch passed into the reasoning layer."""

    suspicious_ip: str
    event_count: int
    source_modules: list[str]
    raw_events: list[dict]
    repeat_offender_count: int = 0
    target_identifier: str
