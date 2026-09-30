"""ui/panels/range_frame.py — Cyber Range simulator control panel for demo validation."""

from typing import Callable
import customtkinter as ctk
from ui.theme import Theme


class RangeFrame(ctk.CTkFrame):
    """Right bottom panel hosting safe loopback attack simulation triggers."""

    def __init__(self, master, on_simulate: Callable[[str], None]):
        super().__init__(
            master,
            fg_color=Theme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=Theme.BORDER_COLOR,
        )
        self._on_simulate = on_simulate
        self._build_widgets()

    def _build_widgets(self) -> None:
        # Title
        self.title_label = ctk.CTkLabel(
            self,
            text="CYBER RANGE — SIMULATOR",
            font=Theme.FONT_SUBTITLE,
            text_color=Theme.CYAN,
            anchor="w",
        )
        self.title_label.pack(fill="x", padx=16, pady=(12, 2))

        self.subtitle = ctk.CTkLabel(
            self,
            text="HARD-LOCKED TO 127.0.0.1 (ZERO EXTERNAL RISK)",
            font=Theme.FONT_BADGE,
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        )
        self.subtitle.pack(fill="x", padx=16, pady=(0, 10))

        # Simulator Buttons Container
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # Button 1: Brute Force
        self.btn_brute = ctk.CTkButton(
            btn_frame,
            text="⚡ SIMULATE BRUTE FORCE (T1110)",
            font=Theme.FONT_SUBTITLE,
            fg_color=Theme.BG_CARD,
            hover_color=Theme.BORDER_COLOR,
            border_width=1,
            border_color=Theme.ALERT_RED,
            text_color=Theme.TEXT_PRIMARY,
            height=34,
            command=lambda: self._on_simulate("bruteforce"),
        )
        self.btn_brute.pack(fill="x", pady=3)

        # Button 2: Port Recon
        self.btn_scan = ctk.CTkButton(
            btn_frame,
            text="🔍 SIMULATE PORT SCAN (T1046)",
            font=Theme.FONT_SUBTITLE,
            fg_color=Theme.BG_CARD,
            hover_color=Theme.BORDER_COLOR,
            border_width=1,
            border_color=Theme.WARN_YELLOW,
            text_color=Theme.TEXT_PRIMARY,
            height=34,
            command=lambda: self._on_simulate("portscan"),
        )
        self.btn_scan.pack(fill="x", pady=3)

        # Button 3: Canary Tampering
        self.btn_canary = ctk.CTkButton(
            btn_frame,
            text="🪤 TRIGGER CANARY TAMPER (T1486)",
            font=Theme.FONT_SUBTITLE,
            fg_color=Theme.BG_CARD,
            hover_color=Theme.BORDER_COLOR,
            border_width=1,
            border_color=Theme.CYAN,
            text_color=Theme.TEXT_PRIMARY,
            height=34,
            command=lambda: self._on_simulate("canary"),
        )
        self.btn_canary.pack(fill="x", pady=3)

        # Latency Readout Banner
        self.latency_card = ctk.CTkFrame(self, fg_color=Theme.BG_CARD, corner_radius=6, height=36)
        self.latency_card.pack(fill="x", padx=14, pady=(0, 12))

        self.latency_label = ctk.CTkLabel(
            self.latency_card,
            text="DEFENSE LATENCY: STANDING BY",
            font=Theme.FONT_BADGE,
            text_color=Theme.CYAN,
        )
        self.latency_label.pack(pady=8)

    def set_last_latency(self, latency_ms: int) -> None:
        """Updates the live latency metric banner."""
        color = Theme.OK_GREEN if latency_ms < 500 else Theme.WARN_YELLOW
        self.latency_label.configure(
            text=f"DEFENSE LATENCY: NEUTRALIZED IN {latency_ms}ms",
            text_color=color,
        )
