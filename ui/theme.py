"""ui/theme.py — Cyberpunk color palette and typography tokens."""


class Theme:
    # Background & Surface Palettes
    BG_ROOT = "#0B0F19"       # Deep obsidian root
    BG_PANEL = "#131826"      # Tactical slate panel
    BG_CARD = "#1A2234"       # Elevated element surface
    BORDER_COLOR = "#222D42"  # Crisp structural borders

    # Cyberpunk Accents & Status Colors
    CYAN = "#00E5FF"          # Terminal primary neon cyan
    OK_GREEN = "#00E676"      # Terminal green for armed & authorized
    ALERT_RED = "#FF3366"     # Alert crimson for critical incidents & rogue assets
    WARN_YELLOW = "#FFD600"   # Warning amber for high/medium severity
    PURPLE_ACCENT = "#7C4DFF" # Antigravity AI reasoning accent

    # Typography Colors
    TEXT_PRIMARY = "#FFFFFF"
    TEXT_MUTED = "#8892B0"
    TEXT_DARK = "#4A5568"

    # Font Tokens
    FONT_TITLE = ("Segoe UI", 16, "bold")
    FONT_SUBTITLE = ("Segoe UI", 12, "bold")
    FONT_BODY = ("Segoe UI", 11)
    FONT_MONO = ("Consolas", 11)
    FONT_MONO_SMALL = ("Consolas", 10)
    FONT_BADGE = ("Segoe UI", 10, "bold")
