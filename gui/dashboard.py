from typing import Optional

import customtkinter as ctk

from gui.theme import TEXT, TEXT_MUTED, SURFACE2, ACCENT, SUCCESS, DANGER, WARNING


class SeverityPieChart(ctk.CTkCanvas):
    def __init__(self, parent, size: int = 120, **kwargs):
        from gui.theme import BG
        super().__init__(parent, width=size, height=size,
                         bg=BG[1], highlightthickness=0, **kwargs)
        self._size = size
        self._data: dict[str, int] = {}

    def set_data(self, counts: dict[str, int]) -> None:
        self._data = counts
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        total = sum(self._data.values())
        if total == 0:
            cx = cy = self._size // 2
            r = self._size // 2 - 4
            self.create_oval(cx - r, cy - r, cx + r, cy + r,
                             outline=SURFACE2, fill="", width=2)
            self.create_text(cx, cy, text="0", fill=TEXT_MUTED[1], font=("Menlo", 14, "bold"))
            return
        colors_map = {"CRITICAL": "#FF3B30", "HIGH": "#FF9500",
                      "MEDIUM": "#FFCC00", "LOW": "#8E8E93", "INFO": "#5AC8FA"}
        cx = cy = self._size // 2
        r = self._size // 2 - 4
        start_angle = 90.0
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = self._data.get(sev, 0)
            if count == 0:
                continue
            extent = (count / total) * 360.0
            self.create_arc(cx - r, cy - r, cx + r, cy + r,
                            start=start_angle, extent=extent,
                            fill=colors_map.get(sev, "#999"),
                            outline="", width=1)
            start_angle += extent
        self.create_oval(cx - r // 3, cy - r // 3,
                         cx + r // 3, cy + r // 3,
                         fill="", outline="")


class RiskMeter(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._label = ctk.CTkLabel(self, text="Risk: --",
                                   font=ctk.CTkFont(size=28, weight="bold"),
                                   text_color=TEXT)
        self._label.pack(expand=True)
        self._sev_label = ctk.CTkLabel(self, text="No data",
                                       font=ctk.CTkFont(size=12),
                                       text_color=TEXT_MUTED)
        self._sev_label.pack()

    def set_risk(self, score: float) -> None:
        if score >= 85:
            color = DANGER[1]
            sev = "CRITICAL"
        elif score >= 60:
            color = WARNING[1]
            sev = "HIGH"
        elif score >= 40:
            color = ACCENT[1]
            sev = "MEDIUM"
        else:
            color = SUCCESS[1]
            sev = "LOW"
        self._label.configure(text=f"Risk: {score:.0f}", text_color=color)
        self._sev_label.configure(text=sev)


class StatsFrame(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._total_label = self._make_stat(0, "Total", "#5AC8FA")
        self._critical_label = self._make_stat(1, "Critical", "#FF3B30")
        self._high_label = self._make_stat(2, "High", "#FF9500")
        self._file_count_label = self._make_stat(3, "Files", "#8E8E93")

    def _make_stat(self, col: int, title: str, color: str) -> ctk.CTkLabel:
        container = ctk.CTkFrame(self, fg_color=SURFACE2, corner_radius=8)
        container.grid(row=0, column=col, padx=4, pady=4, sticky="ew")
        title_lbl = ctk.CTkLabel(container, text=title,
                                 font=ctk.CTkFont(size=10), text_color=TEXT_MUTED)
        title_lbl.pack(pady=(6, 0))
        lbl = ctk.CTkLabel(container, text="0", font=ctk.CTkFont(size=22, weight="bold"),
                           text_color=color)
        lbl.pack(pady=(0, 6))
        return lbl

    def update(self, total: int, critical: int, high: int, files: int) -> None:
        self._total_label.configure(text=str(total))
        self._critical_label.configure(text=str(critical))
        self._high_label.configure(text=str(high))
        self._file_count_label.configure(text=str(files))
