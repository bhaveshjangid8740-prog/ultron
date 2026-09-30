"""ui/panels/brain_feed_frame.py — Live cyberpunk terminal feed of AI reasoning and telemetry."""

import time
import customtkinter as ctk
from ui.theme import Theme


class BrainFeedFrame(ctk.CTkFrame):
    """Terminal-style scrollable live feed displaying AI reasoning decisions."""

    def __init__(self, master):
        super().__init__(
            master,
            fg_color=Theme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=Theme.BORDER_COLOR,
        )
        self._build_widgets()

    def _build_widgets(self) -> None:
        # Header
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=16, pady=(14, 8))

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="ULTRON CORE — BRAIN FEED",
            font=Theme.FONT_SUBTITLE,
            text_color=Theme.CYAN,
            anchor="w",
        )
        self.title_label.pack(side="left")

        self.ai_engine_badge = ctk.CTkLabel(
            self.header_frame,
            text="[ANTIGRAVITY / GEMINI AGENT]",
            font=Theme.FONT_BADGE,
            text_color=Theme.PURPLE_ACCENT,
        )
        self.ai_engine_badge.pack(side="right")

        # Scrollable Terminal Text Box
        self.terminal = ctk.CTkTextbox(
            self,
            fg_color=Theme.BG_ROOT,
            text_color=Theme.TEXT_PRIMARY,
            font=Theme.FONT_MONO,
            corner_radius=6,
            wrap="word",
        )
        self.terminal.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Initial Boot Greeting in Terminal
        self.append_system_line("System initialized. Ultron SOC agent listening for telemetry signals...")

    def append_system_line(self, line: str) -> None:
        """Appends a standard cyan system message."""
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"> [{timestamp}] {line}\n"
        self._insert_text(formatted)

    def append_triage_event(
        self,
        incident_uid: str,
        risk_score: int,
        severity: str,
        mitre_id: str,
        mitre_tactic: str,
        summary: str,
        recommended_action: str,
        target: str,
    ) -> None:
        """Renders an authoritative structured triage verdict in the terminal."""
        timestamp = time.strftime("%H:%M:%S")
        block = (
            f"─────────────────────────────────────────────────────────────\n"
            f"> [{timestamp}] ⚡ INCIDENT REASONING VERDICT // {incident_uid}\n"
            f"  Target: {target}\n"
            f"  Risk Score: {risk_score}/100 [{severity}]\n"
            f"  MITRE ATT&CK: {mitre_id} — {mitre_tactic}\n"
            f"  Analysis: {summary}\n"
            f"  Recommended Action: {recommended_action.upper()}\n"
            f"─────────────────────────────────────────────────────────────\n"
        )
        self._insert_text(block)

    def _insert_text(self, text: str) -> None:
        self.terminal.configure(state="normal")
        self.terminal.insert("end", text)
        self.terminal.see("end")
        self.terminal.configure(state="disabled")
