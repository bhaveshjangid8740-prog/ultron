"""ui/main_window.py — Main Command Center UI Shell for Project Ultron.

Owns the CustomTkinter root window, grid layout, all child panels, and the
single .after()-driven poll loop draining shared.event_bus.ui_bus on the main thread.
"""

import threading
from typing import Callable, Optional
import customtkinter as ctk

import config
from shared.event_bus import drain_ui_bus
from shared.logger import get_logger
from ui.panels.brain_feed_frame import BrainFeedFrame
from ui.panels.header_frame import HeaderFrame
from ui.panels.radar_frame import RadarFrame
from ui.panels.range_frame import RangeFrame
from ui.panels.shield_log_frame import ShieldLogFrame
from ui.theme import Theme
from ui.voice_alerts import VoiceAlertWorker

logger = get_logger("ui.main_window")


class UltronDashboardApp(ctk.CTk):
    """Root Cyberpunk SOC Command Center Window."""

    def __init__(
        self,
        on_toggle_response_mode: Callable[[str], None],
        on_simulate: Callable[[str], None],
        on_approve_shield: Optional[Callable[[int, int, str, str], None]] = None,
        voice_worker: Optional[VoiceAlertWorker] = None,
    ):
        super().__init__()
        self.title(config.UI_TITLE)
        self.geometry(config.UI_GEOMETRY)
        self.configure(fg_color=Theme.BG_ROOT)

        # Set CustomTkinter visual appearance
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self._on_toggle_response_mode = on_toggle_response_mode
        self._on_simulate = on_simulate
        self._on_approve_shield = on_approve_shield
        self._voice_worker = voice_worker

        self._configure_grid()
        self._build_frames()
        self._start_poll_loop()

    def _configure_grid(self) -> None:
        """3-column layout under a full-width header bar."""
        self.grid_rowconfigure(0, weight=0)  # Header fixed
        self.grid_rowconfigure(1, weight=3)  # Top body
        self.grid_rowconfigure(2, weight=2)  # Bottom body (Range panel)

        self.grid_columnconfigure(0, weight=3)  # Left: Radar (God Eye)
        self.grid_columnconfigure(1, weight=5)  # Center: Brain Feed (Ultron Core) - largest
        self.grid_columnconfigure(2, weight=3)  # Right: Shields & Range

    def _build_frames(self) -> None:
        # Header (Top)
        self.header = HeaderFrame(
            self, on_toggle_response_mode=self._on_toggle_response_mode
        )
        self.header.grid(row=0, column=0, columnspan=3, sticky="nsew", padx=12, pady=(12, 8))

        # Left Column: Radar (God Eye)
        self.radar = RadarFrame(self)
        self.radar.grid(row=1, column=0, rowspan=2, sticky="nsew", padx=(12, 6), pady=(0, 12))

        # Center Column: Brain Feed (Ultron Core)
        self.brain_feed = BrainFeedFrame(self)
        self.brain_feed.grid(row=1, column=1, rowspan=2, sticky="nsew", padx=6, pady=(0, 12))

        # Right Column Top: Shield Log
        self.shield_log = ShieldLogFrame(self, on_approve_action=self._on_approve_shield)
        self.shield_log.grid(row=1, column=2, sticky="nsew", padx=(6, 12), pady=(0, 6))

        # Right Column Bottom: Range Simulator
        self.range_panel = RangeFrame(self, on_simulate=self._handle_simulate_click)
        self.range_panel.grid(row=2, column=2, sticky="nsew", padx=(6, 12), pady=(6, 12))

    def _handle_simulate_click(self, scenario: str) -> None:
        """Dispatches simulation trigger to a background thread to keep UI completely responsive."""
        thread = threading.Thread(
            target=self._on_simulate, args=(scenario,), daemon=True
        )
        thread.start()

    def _start_poll_loop(self) -> None:
        """The single bridge between background threads and Tkinter widgets."""
        self._poll_ui_events()

    def _poll_ui_events(self) -> None:
        events = drain_ui_bus()
        for event in events:
            try:
                self._dispatch_event(event)
            except Exception as ex:
                logger.error("Error dispatching UI event: %s", ex)

        # Reschedule poll tick
        self.after(config.UI_POLL_INTERVAL_MS, self._poll_ui_events)

    def _dispatch_event(self, event: dict) -> None:
        etype = event.get("type")

        if etype == "asset_update":
            self.radar.update_asset(
                ip=event["ip"],
                mac=event["mac"],
                hostname=event.get("hostname"),
                authorized=event.get("authorized", False),
            )
        elif etype == "honeypot_status":
            self.radar.set_honeypot_active(event.get("active", True), event.get("port", 21))
        elif etype == "canary_status":
            self.radar.set_canary_active(event.get("active", True), event.get("trap_count", 3))
        elif etype == "canary_alert":
            self.brain_feed.append_system_line(
                f"CANARY TRIPPED: {event.get('filename')} touched by PID {event.get('pid')} ({event.get('process_name')})"
            )
        elif etype == "honeypot_hit":
            self.brain_feed.append_system_line(
                f"HONEYPOT INTRUSION: {event.get('ip')}:{event.get('port')} -> '{event.get('data')}'"
            )
        elif etype == "brain_triage":
            self.brain_feed.append_triage_event(
                incident_uid=event["incident_uid"],
                risk_score=event["risk_score"],
                severity=event["severity"],
                mitre_id=event["mitre_id"],
                mitre_tactic=event["mitre_tactic"],
                summary=event["summary"],
                recommended_action=event["recommended_action"],
                target=event["target"],
            )
            is_critical = event.get("severity") in ("CRITICAL", "HIGH")
            self.header.set_system_status(critical_open=is_critical)
        elif etype == "shield_deployed":
            self.shield_log.append_deployed_entry(
                shield_type=event["shield_type"],
                target=event["target"],
                latency_ms=event.get("latency_ms"),
                message=event.get("message", "Containment executed."),
            )
            if event.get("latency_ms") is not None:
                self.range_panel.set_last_latency(event["latency_ms"])
        elif etype == "shield_pending":
            self.shield_log.append_pending_approval_card(
                action_id=event["action_id"],
                incident_id=event["incident_id"],
                shield_type=event["shield_type"],
                target=event["target"],
            )
        elif etype == "voice_alert":
            if self._voice_worker:
                self._voice_worker.speak(event.get("text", ""))
        elif etype == "log":
            self.brain_feed.append_system_line(event.get("message", ""))
