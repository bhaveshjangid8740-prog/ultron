"""ui/panels/radar_frame.py — Left panel showing God Eye network assets and deception sensor status."""

from typing import Dict, Optional
import customtkinter as ctk
from ui.theme import Theme


class RadarFrame(ctk.CTkFrame):
    """Network asset topology and sensor readiness display."""

    def __init__(self, master):
        super().__init__(
            master,
            fg_color=Theme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=Theme.BORDER_COLOR,
        )
        self._asset_rows: Dict[str, ctk.CTkFrame] = {}  # mac -> row frame
        self._build_widgets()

    def _build_widgets(self) -> None:
        # Title
        self.title_label = ctk.CTkLabel(
            self,
            text="GOD EYE — RADAR",
            font=Theme.FONT_SUBTITLE,
            text_color=Theme.CYAN,
            anchor="w",
        )
        self.title_label.pack(fill="x", padx=16, pady=(14, 6))

        # Sensor Status Cards
        self.sensor_status_frame = ctk.CTkFrame(self, fg_color=Theme.BG_CARD, corner_radius=6)
        self.sensor_status_frame.pack(fill="x", padx=14, pady=6)

        self.honeypot_label = ctk.CTkLabel(
            self.sensor_status_frame,
            text="HONEYPOT (FTP:21)    ● ARMED",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.OK_GREEN,
            anchor="w",
        )
        self.honeypot_label.pack(fill="x", padx=10, pady=(6, 2))

        self.canary_label = ctk.CTkLabel(
            self.sensor_status_frame,
            text="CANARY FILES (3 TRAPS) ● ARMED",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.OK_GREEN,
            anchor="w",
        )
        self.canary_label.pack(fill="x", padx=10, pady=(2, 6))

        # Assets Subtitle
        self.assets_title = ctk.CTkLabel(
            self,
            text="DISCOVERED NETWORK ASSETS",
            font=Theme.FONT_BADGE,
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        )
        self.assets_title.pack(fill="x", padx=16, pady=(10, 4))

        # Scrollable list for assets
        self.asset_scroll = ctk.CTkScrollableFrame(
            self, fg_color=Theme.BG_ROOT, corner_radius=6
        )
        self.asset_scroll.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def update_asset(self, ip: str, mac: str, hostname: Optional[str], authorized: bool) -> None:
        """Adds or updates a device row in the radar list."""
        mac_key = mac.lower()
        badge_text = "● AUTH" if authorized else "▲ ROGUE"
        badge_color = Theme.OK_GREEN if authorized else Theme.ALERT_RED

        if mac_key in self._asset_rows:
            # Update existing row
            row = self._asset_rows[mac_key]
            # Update labels inside row
            for child in row.winfo_children():
                if getattr(child, "_tag", None) == "badge":
                    child.configure(text=badge_text, text_color=badge_color)
                elif getattr(child, "_tag", None) == "ip":
                    child.configure(text=ip)
            return

        # Create new asset card
        row_frame = ctk.CTkFrame(self.asset_scroll, fg_color=Theme.BG_CARD, corner_radius=6, height=44)
        row_frame.pack(fill="x", pady=3, padx=2)

        left_sub = ctk.CTkFrame(row_frame, fg_color="transparent")
        left_sub.pack(side="left", padx=8, pady=4)

        ip_lbl = ctk.CTkLabel(
            left_sub,
            text=ip,
            font=Theme.FONT_BODY,
            text_color=Theme.TEXT_PRIMARY,
            anchor="w",
        )
        ip_lbl._tag = "ip"
        ip_lbl.pack(anchor="w")

        details_text = f"{mac} | {hostname or 'unknown'}"
        details_lbl = ctk.CTkLabel(
            left_sub,
            text=details_text,
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        )
        details_lbl.pack(anchor="w")

        badge_lbl = ctk.CTkLabel(
            row_frame,
            text=badge_text,
            font=Theme.FONT_BADGE,
            text_color=badge_color,
        )
        badge_lbl._tag = "badge"
        badge_lbl.pack(side="right", padx=10, pady=8)

        self._asset_rows[mac_key] = row_frame

    def set_honeypot_active(self, active: bool, port: int = 21) -> None:
        text = f"HONEYPOT (PORT:{port})    {'● ARMED' if active else '○ INACTIVE'}"
        color = Theme.OK_GREEN if active else Theme.TEXT_MUTED
        self.honeypot_label.configure(text=text, text_color=color)

    def set_canary_active(self, active: bool, trap_count: int = 3) -> None:
        text = f"CANARY ({trap_count} TRAPS)     {'● ARMED' if active else '○ INACTIVE'}"
        color = Theme.OK_GREEN if active else Theme.TEXT_MUTED
        self.canary_label.configure(text=text, text_color=color)
