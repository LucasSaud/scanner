import re
from pathlib import Path
from typing import Optional

import customtkinter as ctk

from gui.theme import TEXT, TEXT_MUTED, SURFACE2, CARD_BG, CARD_BORDER, ACCENT


class IOCInspectorDialog(ctk.CTkToplevel):
    def __init__(self, parent, findings: list):
        super().__init__(parent)
        self.title("IOC Inspector — Extracted Indicators")
        self.geometry("600x450")
        self.minsize(400, 300)
        self._extracted: dict[str, list[str]] = {}
        self._extract_iocs(findings)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="IOC Inspector",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(header, text="Close", width=60,
                      command=self.destroy,
                      fg_color=SURFACE2, text_color=TEXT,
                      hover_color=CARD_BORDER).grid(row=0, column=2, sticky="e")

        tabview = ctk.CTkTabview(self, fg_color=CARD_BG,
                                 segmented_button_fg_color=SURFACE2,
                                 segmented_button_selected_color=ACCENT[1])
        tabview.grid(row=1, column=0, sticky="nsew", padx=12, pady=(4, 12))

        for category in ("URLs", "IPs", "Webhooks", "Domains"):
            tab = tabview.add(category)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

            items = self._extracted.get(category.lower(), [])
            if not items:
                ctk.CTkLabel(tab, text="No indicators found.",
                             font=ctk.CTkFont(size=12), text_color=TEXT_MUTED
                             ).grid(row=0, column=0, pady=40)
                continue

            textbox = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Menlo", size=12),
                                     fg_color=CARD_BG, text_color=TEXT,
                                     border_width=0, wrap="none")
            textbox.grid(row=0, column=0, sticky="nsew")
            textbox.insert("1.0", "\n".join(items))
            textbox.configure(state="disabled")

            count = ctk.CTkLabel(tab, text=f"{len(items)} indicator(s)",
                                 font=ctk.CTkFont(size=10), text_color=TEXT_MUTED)
            count.grid(row=1, column=0, sticky="e", pady=(4, 0))

    def _extract_iocs(self, findings: list) -> None:
        urls: set[str] = set()
        ips: set[str] = set()
        webhooks: set[str] = set()
        domains: set[str] = set()
        for f in findings:
            evidence = getattr(f, "evidence", "") or ""
            desc = getattr(f, "description", "") or ""
            terms = getattr(f, "detected_terms", []) or []
            text = f"{evidence} {desc} {' '.join(terms)}"

            for m in re.finditer(r'https?://[^\s"\'<>]+', text):
                url = m.group().rstrip(".,;:")[:120]
                urls.add(url)
                if "webhook" in url.lower() or "discord" in url.lower() or "slack" in url.lower():
                    webhooks.add(url)

            for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
                ips.add(m.group())

            for m in re.finditer(r'(?:ngrok|pastebin|requestbin|hookbin|burpcollaborator|interactsh)\.\w+', text.lower()):
                domains.add(m.group())

        if urls:
            self._extracted["urls"] = sorted(urls)[:50]
        if ips:
            self._extracted["ips"] = sorted(ips)[:50]
        if webhooks:
            self._extracted["webhooks"] = sorted(webhooks)[:50]
        if domains:
            self._extracted["domains"] = sorted(domains)[:25]
