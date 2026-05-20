from typing import Optional

import customtkinter as ctk

from gui.theme import TEXT, TEXT_MUTED, SURFACE2, CARD_BG, CARD_BORDER, ACCENT


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent, settings: Optional[dict] = None,
                 on_save=None):
        super().__init__(parent)
        self.title("Settings")
        self.geometry("500x400")
        self.minsize(400, 300)
        self._on_save = on_save
        self._settings = settings or {}
        self._vars: dict[str, ctk.BooleanVar] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="Scanner Settings",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(header, text="Save", width=60,
                      command=self._save,
                      fg_color=ACCENT[1], text_color="white",
                      hover_color=ACCENT[0]).grid(row=0, column=2, sticky="e", padx=(8, 0))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 16))
        scroll.grid_columnconfigure(1, weight=1)

        self._build_scanner_toggles(scroll)
        self._build_export_options(scroll)

        ctk.CTkButton(self, text="Close", command=self.destroy,
                      fg_color=SURFACE2, text_color=TEXT,
                      hover_color=CARD_BORDER).grid(row=2, column=0, pady=(0, 12))

    def _build_scanner_toggles(self, parent) -> None:
        ctk.CTkLabel(parent, text="Scanners",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, columnspan=2, sticky="w", pady=(8, 4))
        scanners = [
            ("project", "Project Scanner"),
            ("git", "Git Scanner"),
            ("docker", "Docker Scanner"),
            ("env", "Env Scanner"),
            ("yaml", "YAML Scanner"),
            ("global_vscode", "Global VSCode Scan"),
        ]
        for i, (key, label) in enumerate(scanners):
            var = ctk.BooleanVar(value=self._settings.get(key, True))
            self._vars[key] = var
            switch = ctk.CTkSwitch(parent, text=label, variable=var,
                                   font=ctk.CTkFont(size=12), text_color=TEXT,
                                   progress_color=ACCENT[1],
                                   fg_color=SURFACE2)
            switch.grid(row=i + 1, column=0, columnspan=2, sticky="w", padx=8, pady=3)

    def _build_export_options(self, parent) -> None:
        row_start = 8
        ctk.CTkLabel(parent, text="Export Defaults",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=TEXT).grid(row=row_start, column=0, columnspan=2,
                                           sticky="w", pady=(16, 4))
        ctk.CTkLabel(parent, text="Format:",
                     font=ctk.CTkFont(size=12), text_color=TEXT_MUTED
                     ).grid(row=row_start + 1, column=0, sticky="w", padx=8)
        format_var = ctk.StringVar(value=self._settings.get("export_format", "json"))
        format_menu = ctk.CTkOptionMenu(parent, values=["json", "md", "html", "pdf"],
                                        variable=format_var,
                                        fg_color=SURFACE2, text_color=TEXT,
                                        button_color=ACCENT[1],
                                        button_hover_color=ACCENT[0])
        format_menu.grid(row=row_start + 1, column=1, sticky="w", padx=8)

    def _save(self) -> None:
        result = {}
        for key, var in self._vars.items():
            result[key] = var.get()
        result["export_format"] = self._settings.get("export_format", "json")
        if self._on_save:
            self._on_save(result)
        self.destroy()
