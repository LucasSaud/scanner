from typing import Any

import customtkinter as ctk

from gui.theme import TEXT, TEXT_MUTED, SURFACE2, CARD_BG, CARD_BORDER

CRITICAL_COLOR = "#FF3B30"
HIGH_COLOR = "#FF9500"
MEDIUM_COLOR = "#FFCC00"
LOW_COLOR = "#8E8E93"
INFO_COLOR = "#5AC8FA"


class CorrelationCard(ctk.CTkFrame):
    def __init__(self, parent, event: dict[str, Any], **kwargs):
        super().__init__(parent, fg_color=CARD_BG, corner_radius=8,
                         border_width=1, border_color=CARD_BORDER, **kwargs)
        self.event = event
        self._build()

    def _build(self):
        severity = self.event.get("severity", "MEDIUM")
        color = {"CRITICAL": CRITICAL_COLOR, "HIGH": HIGH_COLOR,
                 "MEDIUM": MEDIUM_COLOR, "LOW": LOW_COLOR}.get(severity, INFO_COLOR)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(10, 4))

        badge = ctk.CTkLabel(header, text=severity,
                             fg_color=color, text_color="white",
                             corner_radius=4, font=ctk.CTkFont(size=10, weight="bold"),
                             width=60)
        badge.pack(side="left", padx=(0, 8))

        name = ctk.CTkLabel(header, text=self.event.get("name", ""),
                            font=ctk.CTkFont(size=13, weight="bold"),
                            text_color=TEXT)
        name.pack(side="left", fill="x", expand=True)

        score_text = f"Score: {self.event.get('score', 0):.0f}"
        score_lbl = ctk.CTkLabel(header, text=score_text,
                                 font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        score_lbl.pack(side="right")

        rule_lbl = ctk.CTkLabel(self, text=f"Rule: {self.event.get('rule_id', '')}",
                                font=ctk.CTkFont(size=10), text_color=TEXT_MUTED)
        rule_lbl.pack(anchor="w", padx=12, pady=(0, 2))

        desc = ctk.CTkLabel(self, text=self.event.get("description", ""),
                            font=ctk.CTkFont(size=11), text_color=TEXT_MUTED,
                            wraplength=500, justify="left")
        desc.pack(anchor="w", padx=12, pady=(0, 4))

        finding_ids = self.event.get("finding_ids", [])
        if finding_ids:
            ids_text = f"Findings: {', '.join(finding_ids[:5])}"
            if len(finding_ids) > 5:
                ids_text += f" +{len(finding_ids) - 5} more"
            ids_lbl = ctk.CTkLabel(self, text=ids_text,
                                   font=ctk.CTkFont(size=10), text_color=TEXT_MUTED)
            ids_lbl.pack(anchor="w", padx=12, pady=(0, 8))

        rec = self.event.get("recommendation", "")
        if rec:
            rec_frame = ctk.CTkFrame(self, fg_color=SURFACE2, corner_radius=4)
            rec_frame.pack(fill="x", padx=12, pady=(0, 10))
            rec_lbl = ctk.CTkLabel(rec_frame, text=f"Recommendation: {rec}",
                                   font=ctk.CTkFont(size=10), text_color=TEXT_MUTED,
                                   wraplength=480, justify="left")
            rec_lbl.pack(padx=8, pady=6)


class CorrelationListView(ctk.CTkScrollableFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self._cards: list[CorrelationCard] = []

    def set_events(self, events: list[dict]) -> None:
        for card in self._cards:
            card.destroy()
        self._cards.clear()
        for ev in events:
            card = CorrelationCard(self, ev)
            card.pack(fill="x", padx=4, pady=3)
            self._cards.append(card)

    def clear(self) -> None:
        for card in self._cards:
            card.destroy()
        self._cards.clear()
