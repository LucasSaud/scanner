from typing import Callable, Optional

import customtkinter as ctk

from security_scanner.models import (
    DetectionFinding,
    SEVERITY_BADGE_BG_COLOR,
    SEVERITY_BADGE_TEXT_COLOR,
    SEVERITY_ICON,
    SEVERITY_STRIP_COLOR,
)
from gui.theme import CARD_BG, CARD_HOVER, CARD_BORDER, CARD_STRIP_W


class FindingCard(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        finding: DetectionFinding,
        on_click_callback: Callable[[DetectionFinding], None],
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.finding = finding
        self.on_click_callback = on_click_callback
        self._selected = False
        self.configure(
            corner_radius=8,
            fg_color=CARD_BG,
            border_width=1,
            border_color=CARD_BORDER,
            cursor="pointinghand",
        )
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self._build()
        self._bind_events()

    def _build(self):
        strip_color = SEVERITY_STRIP_COLOR[self.finding.severity]
        self._strip = ctk.CTkFrame(
            self,
            width=CARD_STRIP_W,
            corner_radius=0,
            fg_color=strip_color,
        )
        self._strip.grid(row=0, column=0, rowspan=2, sticky="ns")
        self._strip.grid_propagate(False)

        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=1, sticky="ew", padx=(6, 12), pady=(10, 0))
        header_frame.grid_columnconfigure(1, weight=1)

        icon = ctk.CTkLabel(
            header_frame,
            text=SEVERITY_ICON[self.finding.severity],
            text_color=strip_color,
            font=ctk.CTkFont(size=10),
            width=18,
        )
        icon.grid(row=0, column=0, sticky="w")

        self._file_label = ctk.CTkLabel(
            header_frame,
            text=str(self.finding.file_path.name),
            font=ctk.CTkFont(family="Menlo", size=11),
            text_color=("gray45", "gray65"),
            anchor="w",
        )
        self._file_label.grid(row=0, column=1, sticky="w", padx=(6, 0))

        self._desc_label = ctk.CTkLabel(
            self,
            text=self.finding.description,
            font=ctk.CTkFont(size=12),
            anchor="w",
            justify="left",
            wraplength=0,
        )
        self._desc_label.grid(row=1, column=1, sticky="ew", padx=(6, 12), pady=(2, 10))

    def _bind_events(self):
        def _on_click(_e):
            self.on_click_callback(self.finding)

        def _on_enter(_e):
            if not self._selected:
                self.configure(fg_color=CARD_HOVER)

        def _on_leave(_e):
            if not self._selected:
                self.configure(fg_color=CARD_BG)

        self.bind("<Button-1>", _on_click)
        self._strip.bind("<Button-1>", _on_click)
        self._file_label.bind("<Button-1>", _on_click)
        self._desc_label.bind("<Button-1>", _on_click)
        self.bind("<Enter>", _on_enter)
        self.bind("<Leave>", _on_leave)

    def set_selected(self, selected: bool):
        self._selected = selected
        if selected:
            self.configure(fg_color=CARD_HOVER, border_color=SEVERITY_STRIP_COLOR[self.finding.severity])
        else:
            self.configure(fg_color=CARD_BG, border_color=CARD_BORDER)


class SkeletonCard(ctk.CTkFrame):
    SKELETON_BG = ("gray90", "gray20")

    def __init__(self, parent, **kwargs):
        super().__init__(parent, corner_radius=8, fg_color=self.SKELETON_BG, height=62, **kwargs)
        self.grid_propagate(False)
        self.grid_columnconfigure(1, weight=1)
        self._pulse_id: Optional[str] = None
        self._pulse_alpha = 0.3
        self._build()

    def _build(self):
        self._strip_placeholder = ctk.CTkFrame(
            self, width=CARD_STRIP_W, corner_radius=0, fg_color=("gray80", "gray30")
        )
        self._strip_placeholder.grid(row=0, column=0, rowspan=2, sticky="ns")
        self._strip_placeholder.grid_propagate(False)

        self._bar1 = ctk.CTkLabel(
            self, text="", fg_color=("gray80", "gray30"), corner_radius=4, width=160, height=12
        )
        self._bar1.grid(row=0, column=1, padx=(6, 0), pady=(12, 3), sticky="w")

        self._bar2 = ctk.CTkLabel(
            self, text="", fg_color=("gray80", "gray30"), corner_radius=4, width=320, height=12
        )
        self._bar2.grid(row=1, column=1, padx=(6, 0), pady=(0, 12), sticky="w")

    def start_pulse(self):
        self._pulse()

    def _pulse(self):
        if not self.winfo_exists():
            self._pulse_id = None
            return
        from math import sin
        self._pulse_alpha = 0.3 + abs(sin(self._pulse_alpha * 3.14)) * 0.2
        alpha = max(0.2, min(0.5, self._pulse_alpha))
        shade1 = f"gray{int(90 + (1 - alpha) * 50)}"
        shade2 = f"gray{int(20 + (1 - alpha) * 30)}"
        bar_shade1 = f"gray{int(80 + (1 - alpha) * 50)}"
        bar_shade2 = f"gray{int(30 + (1 - alpha) * 30)}"
        self.configure(fg_color=(shade1, shade2))
        self._strip_placeholder.configure(fg_color=(bar_shade1, bar_shade2))
        self._bar1.configure(fg_color=(bar_shade1, bar_shade2))
        self._bar2.configure(fg_color=(bar_shade1, bar_shade2))
        self._pulse_alpha += 0.05
        self._pulse_id = self.after(120, self._pulse)

    def stop_pulse(self):
        if self._pulse_id:
            self.after_cancel(self._pulse_id)
            self._pulse_id = None
