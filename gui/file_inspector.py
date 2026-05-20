from pathlib import Path

import customtkinter as ctk

from gui.theme import TEXT, TEXT_MUTED, SURFACE2, CARD_BG, CARD_BORDER


class FileInspectorDialog(ctk.CTkToplevel):
    def __init__(self, parent, file_path: Path, content: str,
                 findings: list[dict] | None = None):
        super().__init__(parent)
        self.title(f"File Inspector — {file_path.name}")
        self.geometry("700x500")
        self.minsize(500, 300)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text=f"File: {file_path}",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w")

        close_btn = ctk.CTkButton(header, text="Close", width=60,
                                  command=self.destroy,
                                  fg_color=SURFACE2, text_color=TEXT,
                                  hover_color=CARD_BORDER)
        close_btn.grid(row=0, column=2, sticky="e", padx=(8, 0))

        findings_text = f"{len(findings)} finding(s)" if findings else ""
        if findings_text:
            ctk.CTkLabel(header, text=findings_text,
                         font=ctk.CTkFont(size=10), text_color=TEXT_MUTED
                         ).grid(row=1, column=0, sticky="w")

        textbox = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Menlo", size=11),
                                 fg_color=CARD_BG, text_color=TEXT,
                                 border_width=1, border_color=CARD_BORDER,
                                 wrap="none")
        textbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(4, 12))

        lines = content.split("\n")
        max_lineno = len(lines)
        pad = len(str(max_lineno))
        annotated_lines: list[str] = []
        for i, line in enumerate(lines, 1):
            marker = ""
            if findings:
                for f in findings:
                    fl = f.get("line")
                    if fl is not None and fl == i:
                        marker = "  ← FINDING"
                        break
            annotated_lines.append(f"{str(i).rjust(pad)} | {line}{marker}")
        textbox.insert("1.0", "\n".join(annotated_lines))
        textbox.configure(state="disabled")
