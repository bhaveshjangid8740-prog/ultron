"""ui/panels/header_frame.py — Top command bar with title, armed indicator, and autonomy toggle."""

from typing import Callable
import customtkinter as ctk
from shields.privilege_check import is_elevated
from ui.theme import Theme


class HeaderFrame(ctk.CTkFrame):
    """Top banner for system status and autonomy response toggle."""

    def __init__(self, master, on_toggle_response_mode: Callable[[str], None]):
        super().__init__(
            master,
            fg_color=Theme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=Theme.BORDER_COLOR,
            height=60,
        )
        self._on_toggle_response_mode = on_toggle_response_mode
        self._is_critical = False

        self._build_widgets()

    def _build_widgets(self) -> None:
        # 1. Title / Branding
        self.title_label = ctk.CTkLabel(
            self,
            text="⛨ ULTRON // GOD'S EYE",
            font=Theme.FONT_TITLE,
            text_color=Theme.CYAN,
        )
        self.title_label.pack(side="left", padx=20, pady=12)

        self.subtitle_label = ctk.CTkLabel(
            self,
            text="AUTONOMOUS SOC AGENT",
            font=Theme.FONT_BADGE,
            text_color=Theme.TEXT_MUTED,
        )
        self.subtitle_label.pack(side="left", padx=(0, 25), pady=14)

        # 2. Privilege Indicator
        elevated = is_elevated()
        priv_text = "SHIELDS: ELEVATED" if elevated else "SHIELDS: SAFE SIMULATION"
        priv_color = Theme.OK_GREEN if elevated else Theme.WARN_YELLOW
        self.priv_badge = ctk.CTkLabel(
            self,
            text=f"[{priv_text}]",
            font=Theme.FONT_BADGE,
            text_color=priv_color,
        )
        self.priv_badge.pack(side="left", padx=10, pady=14)

        # 3. Mode Toggle (Right side)
        self.mode_label = ctk.CTkLabel(
            self,
            text="AUTONOMOUS",
            font=Theme.FONT_SUBTITLE,
            text_color=Theme.OK_GREEN,
        )
        self.mode_label.pack(side="right", padx=(10, 20), pady=14)

        self.mode_switch = ctk.CTkSwitch(
            self,
            text="",
            command=self._handle_switch_toggled,
            onvalue=1,
            offvalue=0,
            progress_color=Theme.CYAN,
            button_color=Theme.TEXT_PRIMARY,
            button_hover_color=Theme.CYAN,
            width=48,
        )
        self.mode_switch.select()  # Default to AUTONOMOUS (1)
        self.mode_switch.pack(side="right", padx=5, pady=14)

        self.mode_title = ctk.CTkLabel(
            self,
            text="CONTAINMENT MODE:",
            font=Theme.FONT_BADGE,
            text_color=Theme.TEXT_MUTED,
        )
        self.mode_title.pack(side="right", padx=5, pady=14)

        # 4. Status Indicator (Center right)
        self.status_dot = ctk.CTkLabel(
            self,
            text="● SYSTEM ARMED",
            font=Theme.FONT_SUBTITLE,
            text_color=Theme.OK_GREEN,
        )
        self.status_dot.pack(side="right", padx=25, pady=14)

    def set_system_status(self, critical_open: bool = False) -> None:
        """Updates status dot color when critical threats occur."""
        self._is_critical = critical_open
        if critical_open:
            self.status_dot.configure(text="▲ THREAT CONTAINMENT ACTIVE", text_color=Theme.ALERT_RED)
        else:
            self.status_dot.configure(text="● SYSTEM ARMED", text_color=Theme.OK_GREEN)

    def _handle_switch_toggled(self) -> None:
        """Main thread callback switching AUTONOMOUS <-> HUMAN_APPROVAL."""
        is_auto = self.mode_switch.get() == 1
        if is_auto:
            self.mode_label.configure(text="AUTONOMOUS", text_color=Theme.OK_GREEN)
            self._on_toggle_response_mode("AUTONOMOUS")
        else:
            self.mode_label.configure(text="HUMAN APPROVAL", text_color=Theme.WARN_YELLOW)
            self._on_toggle_response_mode("HUMAN_APPROVAL")
