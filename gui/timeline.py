from typing import Any

import customtkinter as ctk

from gui.theme import TEXT, TEXT_MUTED, SURFACE2, CARD_BG, CARD_BORDER

SEV_COLORS = {"CRITICAL": "#FF3B30", "HIGH": "#FF9500",
              "MEDIUM": "#FFCC00", "LOW": "#8E8E93", "INFO": "#5AC8FA"}


class TimelineEntry(ctk.CTkFrame):
    def __init__(self, parent, finding_dict: dict[str, Any], index: int, **kwargs):
        super().__init__(parent, fg_color=CARD_BG, corner_radius=8,
                         border_width=1, border_color=CARD_BORDER, **kwargs)
        self._build(finding_dict, index)

    def _build(self, f: dict, idx: int):
        sev = f.get("severity", "MEDIUM")
        color = SEV_COLORS.get(sev, "#999")

        dot = ctk.CTkFrame(self, width=10, height=10, corner_radius=5,
                           fg_color=color)
        dot.place(x=8, rely=0.5, anchor="w")

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=(24, 12), pady=(8, 2))

        num = ctk.CTkLabel(header, text=f"#{idx}",
                           font=ctk.CTkFont(size=11, weight="bold"),
                           text_color=TEXT_MUTED)
        num.pack(side="left", padx=(0, 6))

        badge = ctk.CTkLabel(header, text=sev,
                             fg_color=color, text_color="white",
                             corner_radius=3, font=ctk.CTkFont(size=9, weight="bold"),
                             width=50)
        badge.pack(side="left", padx=(0, 6))

        desc = ctk.CTkLabel(header, text=f.get("description", ""),
                            font=ctk.CTkFont(size=12),
                            text_color=TEXT)
        desc.pack(side="left", fill="x", expand=True)

        score = ctk.CTkLabel(header, text=f"Score: {f.get('score', 0):.0f}",
                             font=ctk.CTkFont(size=10), text_color=TEXT_MUTED)
        score.pack(side="right")

        meta = ctk.CTkFrame(self, fg_color="transparent")
        meta.pack(fill="x", padx=(24, 12), pady=(0, 8))

        file_text = f.get("file", "")
        if file_text:
            ctk.CTkLabel(meta, text=f"File: {file_text}",
                         font=ctk.CTkFont(size=10, family="Menlo"),
                         text_color=TEXT_MUTED).pack(side="left", padx=(0, 12))

        line = f.get("line")
        if line:
            ctk.CTkLabel(meta, text=f"Line: {line}",
                         font=ctk.CTkFont(size=10),
                         text_color=TEXT_MUTED).pack(side="left")

        cat = f.get("category", "")
        if cat:
            ctk.CTkLabel(meta, text=f"Category: {cat}",
                         font=ctk.CTkFont(size=10),
                         text_color=TEXT_MUTED).pack(side="right")

        conn = ctk.CTkFrame(self, width=2, height=16, fg_color=SURFACE2,
                            corner_radius=0)
        conn.place(x=12, rely=1.0, anchor="s", height=16, width=2)


class TimelineView(ctk.CTkScrollableFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self._entries: list[TimelineEntry] = []
        self._empty_label: ctk.CTkLabel = ctk.CTkLabel(
            self, text="No findings yet.\nRun a scan to see results.",
            font=ctk.CTkFont(size=14), text_color=TEXT_MUTED
        )

    def set_findings(self, findings: list[dict]) -> None:
        for entry in self._entries:
            entry.destroy()
        self._entries.clear()
        if not findings:
            self._empty_label.pack(expand=True, pady=40)
            return
        self._empty_label.pack_forget()
        for i, f in enumerate(findings, 1):
            entry = TimelineEntry(self, f, i)
            entry.pack(fill="x", padx=4, pady=2)
            self._entries.append(entry)

    def clear(self) -> None:
        self.set_findings([])
