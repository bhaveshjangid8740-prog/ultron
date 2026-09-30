"""ui/panels/shield_log_frame.py — Active defense containment log and approval queue."""

import time
from typing import Callable, Optional
import customtkinter as ctk
from ui.theme import Theme


class ShieldLogFrame(ctk.CTkFrame):
    """Right top panel displaying containment actions and human approval buttons."""

    def __init__(self, master, on_approve_action: Optional[Callable[[int, int, str, str], None]] = None):
        super().__init__(
            master,
            fg_color=Theme.BG_PANEL,
            corner_radius=8,
            border_width=1,
            border_color=Theme.BORDER_COLOR,
        )
        self._on_approve_action = on_approve_action
        self._build_widgets()

    def _build_widgets(self) -> None:
        # Title
        self.title_label = ctk.CTkLabel(
            self,
            text="SHIELD DEPLOYMENT LOG",
            font=Theme.FONT_SUBTITLE,
            text_color=Theme.CYAN,
            anchor="w",
        )
        self.title_label.pack(fill="x", padx=16, pady=(14, 6))

        # Scrollable log for containment records & pending approval cards
        self.scroll_log = ctk.CTkScrollableFrame(
            self, fg_color=Theme.BG_ROOT, corner_radius=6
        )
        self.scroll_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Initial message
        self.append_system_entry("Shields armed and standing by for containment directives...")

    def append_system_entry(self, message: str) -> None:
        """Appends a passive log message."""
        timestamp = time.strftime("%H:%M:%S")
        lbl = ctk.CTkLabel(
            self.scroll_log,
            text=f"[{timestamp}] {message}",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w",
            wraplength=380,
        )
        lbl.pack(fill="x", pady=2, padx=4)

    def append_deployed_entry(
        self, shield_type: str, target: str, latency_ms: Optional[int], message: str
    ) -> None:
        """Renders an executed containment action card."""
        timestamp = time.strftime("%H:%M:%S")
        card = ctk.CTkFrame(self.scroll_log, fg_color=Theme.BG_CARD, corner_radius=6)
        card.pack(fill="x", pady=3, padx=2)

        icon = "✓"
        action_name = shield_type.replace("_", " ")
        header_text = f"{icon} [{timestamp}] {action_name} -> {target}"

        hdr_lbl = ctk.CTkLabel(
            card,
            text=header_text,
            font=Theme.FONT_BODY,
            text_color=Theme.OK_GREEN,
            anchor="w",
        )
        hdr_lbl.pack(fill="x", padx=8, pady=(4, 0))

        latency_text = f"Latency: {latency_ms}ms" if latency_ms is not None else "Latency: <500ms"
        det_lbl = ctk.CTkLabel(
            card,
            text=f"{latency_text} | {message}",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w",
            wraplength=360,
        )
        det_lbl.pack(fill="x", padx=8, pady=(0, 4))

    def append_pending_approval_card(
        self, action_id: int, incident_id: int, shield_type: str, target: str
    ) -> None:
        """Renders a card for human-approval mode with an action button."""
        timestamp = time.strftime("%H:%M:%S")
        card = ctk.CTkFrame(self.scroll_log, fg_color=Theme.BG_CARD, corner_radius=6)
        card.pack(fill="x", pady=4, padx=2)

        hdr_lbl = ctk.CTkLabel(
            card,
            text=f"⚠ [{timestamp}] ACTION PENDING APPROVAL",
            font=Theme.FONT_BODY,
            text_color=Theme.WARN_YELLOW,
            anchor="w",
        )
        hdr_lbl.pack(fill="x", padx=8, pady=(4, 0))

        det_lbl = ctk.CTkLabel(
            card,
            text=f"Target: {target} | Type: {shield_type}",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_PRIMARY,
            anchor="w",
        )
        det_lbl.pack(fill="x", padx=8, pady=(0, 4))

        def on_click():
            btn.configure(state="disabled", text="DEPLOYING...")
            if self._on_approve_action:
                self._on_approve_action(action_id, incident_id, shield_type, target)
            card.destroy()

        btn = ctk.CTkButton(
            card,
            text="DEPLOY SHIELD NOW",
            font=Theme.FONT_BADGE,
            fg_color=Theme.ALERT_RED,
            hover_color="#CC0033",
            text_color="#FFFFFF",
            height=28,
            command=on_click,
        )
        btn.pack(padx=8, pady=(0, 6), anchor="e")
