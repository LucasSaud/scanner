import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

from security_scanner.models import (
    DetectionFinding,
    ScanResult,
    SEVERITY_BADGE_BG_COLOR,
    SEVERITY_BADGE_TEXT_COLOR,
    SEVERITY_ICON,
    SEVERITY_STRIP_COLOR,
    SEVERITY_SORT_PRIORITY,
)
from security_scanner.scanners import ScannerManager
from security_scanner.reporting import JSONReport, MarkdownReport, HTMLReport, PDFReport
from security_scanner.telemetry import telemetry_logger, scan_metrics
from security_scanner.cache import scan_cache

from gui.theme import (
    ACCENT, DANGER, SUCCESS, WARNING,
    BG, SURFACE, SURFACE2,
    TEXT, TEXT_MUTED, TEXT_DIM,
    BORDER, CARD_BG, CARD_HOVER, CARD_BORDER,
    BTN_PRIMARY_FG, BTN_PRIMARY_HVR,
    BTN_DANGER_FG, BTN_DANGER_HVR,
    BTN_SECONDARY_FG, BTN_SECONDARY_HVR,
    PROGRESS_COLOR, PROGRESS_BG,
    SWITCH_BG,
)
from gui.widgets import FindingCard, SkeletonCard
from gui.dashboard import RiskMeter, StatsFrame
from gui.correlation_view import CorrelationListView
from gui.timeline import TimelineView
from gui.file_inspector import FileInspectorDialog
from gui.ioc_inspector import IOCInspectorDialog
from gui.settings import SettingsDialog


class VSCodeSecurityScannerApp(ctk.CTk):
    APP_TITLE = "VSCode Security Scanner"
    WINDOW_GEOMETRY = "980x700"
    WINDOW_MIN_WIDTH = 820
    WINDOW_MIN_HEIGHT = 580

    def __init__(self):
        super().__init__()
        self._all_findings: list[DetectionFinding] = []
        self._last_result: Optional[ScanResult] = None
        self._is_scan_running = False
        self._selected_scan_directory = ctk.StringVar(value="")
        self._should_scan_global_vscode = ctk.BooleanVar(value=True)
        self._skeleton_cards: list[SkeletonCard] = []
        self._current_finding: Optional[DetectionFinding] = None
        self._selected_card: Optional[FindingCard] = None
        self._scanner_manager = ScannerManager()

        self.title(self.APP_TITLE)
        self.geometry(self.WINDOW_GEOMETRY)
        self.minsize(self.WINDOW_MIN_WIDTH, self.WINDOW_MIN_HEIGHT)
        self._build_complete_layout()

    def _build_complete_layout(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_top_header_bar()
        self._build_main_two_column_area()
        self._build_bottom_status_bar()

    def _build_top_header_bar(self):
        header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=SURFACE)
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(1, weight=1)
        header_frame.grid_propagate(False)
        header_frame.configure(height=92)

        # Accent line at bottom of header
        accent_line = ctk.CTkFrame(header_frame, height=2, corner_radius=0, fg_color=ACCENT)
        accent_line.grid(row=1, column=0, sticky="ew")
        accent_line.grid_propagate(False)

        titles_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        titles_frame.grid(row=0, column=0, padx=18, pady=(16, 0), sticky="w")
        ctk.CTkLabel(
            titles_frame,
            text="VSCode Security Scanner",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT,
        ).pack(anchor="w")
        ctk.CTkLabel(
            titles_frame,
            text="Detecta malware em projetos clonados do GitHub",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(2, 0))
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.grid(row=0, column=1, padx=18, pady=(16, 0), sticky="e")
        ctk.CTkSwitch(
            controls_frame,
            text="Incluir ~/.vscode global",
            variable=self._should_scan_global_vscode,
            font=ctk.CTkFont(size=12),
            fg_color=SWITCH_BG,
            progress_color=ACCENT,
        ).grid(row=0, column=0, columnspan=4, padx=(0, 4), pady=(0, 8), sticky="e")
        directory_entry = ctk.CTkEntry(
            controls_frame,
            textvariable=self._selected_scan_directory,
            placeholder_text="Selecione ou cole o caminho da pasta...",
            placeholder_text_color=TEXT_MUTED,
            width=300,
            height=34,
            font=ctk.CTkFont(size=12),
            fg_color=CARD_BG,
            border_color=BORDER,
        )
        directory_entry.grid(row=1, column=0, padx=(0, 6))
        ctk.CTkButton(
            controls_frame,
            text="\u00a0\u00a0\u25c1\u00a0Browse\u00a0\u00a0",
            width=80,
            height=34,
            font=ctk.CTkFont(size=12),
            fg_color=BTN_SECONDARY_FG,
            text_color=TEXT,
            hover_color=BTN_SECONDARY_HVR,
            command=self._open_native_directory_picker_dialog,
        ).grid(row=1, column=1, padx=(0, 6))
        self._scan_action_button = ctk.CTkButton(
            controls_frame,
            text="Iniciar Scan",
            width=120,
            height=34,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=ACCENT,
            text_color="white",
            hover_color=BTN_PRIMARY_HVR,
            command=self._start_scan_in_background_thread,
        )
        self._scan_action_button.grid(row=1, column=2, padx=(0, 4))
        ctk.CTkButton(
            controls_frame,
            text="\u22ee",
            width=30,
            height=34,
            font=ctk.CTkFont(size=18),
            fg_color="transparent",
            text_color=TEXT_MUTED,
            hover_color=SURFACE2,
            command=self._show_info_menu,
        ).grid(row=1, column=3)

    def _build_main_two_column_area(self):
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=8)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_rowconfigure(0, weight=3)
        content_frame.grid_rowconfigure(1, weight=2)
        self._build_left_summary_sidebar(content_frame)
        self._build_right_findings_list_panel(content_frame)
        self._build_right_finding_detail_panel(content_frame)

    def _build_left_summary_sidebar(self, parent):
        sidebar = ctk.CTkFrame(parent, width=200, corner_radius=10, fg_color=SURFACE)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="ns", padx=(0, 10))
        sidebar.grid_propagate(False)

        # Section header
        ctk.CTkLabel(
            sidebar,
            text="RESUMO",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(padx=16, pady=(18, 4), anchor="w")
        ctk.CTkFrame(sidebar, height=2, width=28, corner_radius=1, fg_color=ACCENT).pack(
            padx=16, pady=(0, 14), anchor="w"
        )

        # Severity rows with icons
        self._severity_count_labels: dict[str, ctk.CTkLabel] = {}
        for severity in SEVERITY_SORT_PRIORITY:
            row = ctk.CTkFrame(sidebar, fg_color="transparent")
            row.pack(padx=16, pady=3, fill="x")
            icon_color = SEVERITY_STRIP_COLOR[severity]
            ctk.CTkLabel(
                row,
                text=SEVERITY_ICON[severity],
                text_color=icon_color,
                font=ctk.CTkFont(size=12),
                width=16,
                anchor="center",
            ).pack(side="left")
            ctk.CTkLabel(
                row,
                text=severity,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=TEXT,
                anchor="w",
            ).pack(side="left", padx=(6, 0))
            count = ctk.CTkLabel(
                row,
                text="\u2014",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=TEXT,
                anchor="e",
            )
            count.pack(side="right")
            self._severity_count_labels[severity] = count

        # Divider
        ctk.CTkFrame(sidebar, height=1, fg_color=BORDER).pack(
            padx=16, pady=16, fill="x"
        )

        # Progress section
        ctk.CTkLabel(
            sidebar,
            text="PROGRESSO",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(padx=16, pady=(0, 8), anchor="w")
        self._scan_progress_bar = ctk.CTkProgressBar(
            sidebar, width=168, fg_color=PROGRESS_BG, progress_color=ACCENT
        )
        self._scan_progress_bar.set(0)
        self._scan_progress_bar.pack(padx=16, pady=(0, 4))
        self._scan_progress_percentage_label = ctk.CTkLabel(
            sidebar,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_MUTED,
        )
        self._scan_progress_percentage_label.pack(padx=16, pady=(0, 4))
        self._scan_current_file_label = ctk.CTkLabel(
            sidebar,
            text="",
            font=ctk.CTkFont(size=9),
            text_color=TEXT_DIM,
            wraplength=168,
            justify="left",
            anchor="w",
        )
        self._scan_current_file_label.pack(padx=16, pady=(0, 12), fill="x")

        # Risk meter
        self._risk_meter = RiskMeter(sidebar)
        self._risk_meter.pack(padx=16, pady=(0, 8), fill="x")

        # Stats frame
        self._stats_frame = StatsFrame(sidebar)
        self._stats_frame.pack(padx=16, pady=(0, 8), fill="x")

        # Divider
        ctk.CTkFrame(sidebar, height=1, fg_color=BORDER).pack(
            padx=16, pady=(0, 14), fill="x"
        )

        # Action buttons
        self._export_btn = ctk.CTkButton(
            sidebar,
            text="Exportar",
            width=168,
            height=32,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            text_color=TEXT,
            hover_color=SURFACE2,
            border_width=1,
            border_color=BORDER,
            command=self._export_current_findings,
        )
        self._export_btn.pack(padx=16, pady=3)
        self._ioc_btn = ctk.CTkButton(
            sidebar,
            text="IOC Inspector",
            width=168,
            height=32,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            text_color=TEXT,
            hover_color=SURFACE2,
            border_width=1,
            border_color=BORDER,
            command=self._open_ioc_inspector,
        )
        self._ioc_btn.pack(padx=16, pady=3)
        ctk.CTkButton(
            sidebar,
            text="Limpar resultados",
            width=168,
            height=32,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            text_color=TEXT_MUTED,
            hover_color=SURFACE2,
            border_width=1,
            border_color=BORDER,
            command=self._clear_all_scan_results,
        ).pack(padx=16, pady=3)

    def _build_right_findings_list_panel(self, parent):
        panel = ctk.CTkFrame(parent, corner_radius=10, fg_color=SURFACE)
        panel.grid(row=0, column=1, sticky="nsew", pady=(0, 8))
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        header_frame = ctk.CTkFrame(panel, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=14, pady=(12, 4), sticky="ew")
        ctk.CTkLabel(
            header_frame,
            text="Achados",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT,
        ).pack(side="left")
        self._findings_count_badge = ctk.CTkLabel(
            header_frame,
            text="",
            font=ctk.CTkFont(size=10),
            text_color=TEXT_MUTED,
            fg_color=SURFACE2,
            corner_radius=4,
            padx=6,
        )
        self._findings_count_badge.pack(side="left", padx=(6, 0))
        self._findings_scrollable_list = ctk.CTkScrollableFrame(
            panel, fg_color="transparent"
        )
        self._findings_scrollable_list.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._findings_scrollable_list.grid_columnconfigure(0, weight=1)
        self._empty_state_placeholder_label = ctk.CTkLabel(
            self._findings_scrollable_list,
            text="Nenhum scan realizado ainda.\nEscolha uma pasta e clique em Iniciar Scan.",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
            justify="center",
        )
        self._empty_state_placeholder_label.grid(row=0, column=0, pady=50)

    def _build_right_finding_detail_panel(self, parent):
        panel = ctk.CTkFrame(parent, corner_radius=10, fg_color=SURFACE)
        panel.grid(row=1, column=1, sticky="nsew")
        panel.grid_rowconfigure(0, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        self._detail_tabview = ctk.CTkTabview(
            panel,
            fg_color="transparent",
            segmented_button_fg_color=SURFACE2,
            segmented_button_selected_color=ACCENT,
            text_color=TEXT,
        )
        self._detail_tabview.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        # Detail tab
        detail_tab = self._detail_tabview.add("Detalhe")
        detail_tab.grid_rowconfigure(1, weight=1)
        detail_tab.grid_columnconfigure(0, weight=1)

        view_file_btn = ctk.CTkButton(
            detail_tab,
            text="Ver Arquivo",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="transparent",
            text_color=TEXT,
            hover_color=SURFACE2,
            border_width=1,
            border_color=BORDER,
            command=self._open_file_inspector,
        )
        view_file_btn.grid(row=0, column=0, sticky="e", padx=4, pady=(4, 0))

        self._finding_detail_textbox = ctk.CTkTextbox(
            detail_tab,
            font=ctk.CTkFont(family="Menlo", size=12),
            wrap="word",
            state="disabled",
            fg_color=CARD_BG,
            text_color=TEXT,
            border_width=1,
            border_color=CARD_BORDER,
        )
        self._finding_detail_textbox.grid(row=1, column=0, sticky="nsew", pady=(4, 4))

        # Timeline tab
        timeline_tab = self._detail_tabview.add("Timeline")
        timeline_tab.grid_rowconfigure(0, weight=1)
        timeline_tab.grid_columnconfigure(0, weight=1)
        self._timeline_view = TimelineView(timeline_tab)
        self._timeline_view.grid(row=0, column=0, sticky="nsew")

        # Correlations tab
        corr_tab = self._detail_tabview.add("Correlacoes")
        corr_tab.grid_rowconfigure(0, weight=1)
        corr_tab.grid_columnconfigure(0, weight=1)
        self._correlation_view = CorrelationListView(corr_tab)
        self._correlation_view.grid(row=0, column=0, sticky="nsew")

    def _build_bottom_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=2, column=0, padx=16, pady=(0, 10), sticky="ew")
        bar.grid_columnconfigure(1, weight=1)
        self._status_dot = ctk.CTkLabel(
            bar, text="\u25CF",
            font=ctk.CTkFont(size=8),
            text_color=SUCCESS,
            width=12,
        )
        self._status_dot.grid(row=0, column=0, sticky="w")
        self._status_message_label = ctk.CTkLabel(
            bar,
            text="Pronto. Selecione uma pasta e inicie o scan.",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self._status_message_label.grid(row=0, column=1, sticky="w")

    def _open_native_directory_picker_dialog(self):
        chosen_path = filedialog.askdirectory(title="Selecione a pasta do projeto para escanear")
        if chosen_path:
            self._selected_scan_directory.set(chosen_path)

    def _show_skeleton_loaders(self):
        self._skeleton_cards.clear()
        for widget in self._findings_scrollable_list.winfo_children():
            widget.destroy()
        for _ in range(5):
            card = SkeletonCard(self._findings_scrollable_list)
            card.grid(row=len(self._skeleton_cards), column=0, sticky="ew", padx=4, pady=3)
            card.start_pulse()
            self._skeleton_cards.append(card)

    def _remove_skeleton_loaders(self):
        for card in self._skeleton_cards:
            card.stop_pulse()
            card.destroy()
        self._skeleton_cards.clear()

    def _start_scan_in_background_thread(self):
        if self._is_scan_running:
            return
        self._is_scan_running = True
        self._scanner_manager.reset_stop()
        self._scan_action_button.configure(
            text="\u23f9  Parar",
            fg_color=DANGER,
            text_color="white",
            hover_color=BTN_DANGER_HVR,
            command=self._stop_scan,
        )
        self._clear_all_scan_results()
        self._show_skeleton_loaders()
        self._update_status_bar_message("Iniciando varredura...")
        self._status_dot.configure(text_color=ACCENT)
        scan_thread = threading.Thread(
            target=self._execute_full_scan_and_render_results,
            daemon=True,
        )
        scan_thread.start()

    def _stop_scan(self):
        if not self._is_scan_running:
            return
        self._scanner_manager.stop()
        self._scan_action_button.configure(
            state="disabled",
            text="Parando...",
            fg_color=DANGER,
            text_color="white",
        )
        self._update_status_bar_message("Parando a varredura...")

    def _execute_full_scan_and_render_results(self):
        target_directory = self._selected_scan_directory.get().strip() or "."
        self._update_status_bar_message(f"Varrendo: {target_directory}")

        def on_progress(path_label: str, current: int, total: int):
            ratio = current / total if total > 0 else 0
            short = Path(path_label).name if path_label else ""
            self.after(0, lambda: self._scan_progress_bar.set(ratio))
            self.after(0, lambda: self._scan_progress_percentage_label.configure(
                text=f"{int(ratio * 100)}%"
            ))
            self.after(0, lambda s=short: self._scan_current_file_label.configure(text=s))

        result = self._scanner_manager.scan_path(
            Path(target_directory),
            progress_callback=on_progress,
            include_global=self._should_scan_global_vscode.get(),
        )

        self._last_result = result
        sorted_findings = sorted(
            result.findings,
            key=lambda f: SEVERITY_SORT_PRIORITY.get(f.severity, 9),
        )
        self.after(0, lambda: self._render_scan_results_on_ui(sorted_findings, result))

    def _render_scan_results_on_ui(self, findings: list[DetectionFinding], result: Optional[ScanResult] = None):
        self._remove_skeleton_loaders()
        self._all_findings = findings
        self._finding_cards: list[FindingCard] = []
        sr = result or self._last_result
        total = len(findings)
        self._findings_count_badge.configure(text=f"{total}" if total else "")
        if not findings:
            clean_label = ctk.CTkLabel(
                self._findings_scrollable_list,
                text="Nenhuma amea\u00e7a detectada.",
                font=ctk.CTkFont(size=13),
                text_color=SUCCESS,
            )
            clean_label.grid(row=0, column=0, pady=50)
        else:
            for index, finding in enumerate(findings):
                card = FindingCard(
                    self._findings_scrollable_list,
                    finding,
                    on_click_callback=self._on_finding_card_click,
                )
                card.grid(row=index, column=0, sticky="ew", padx=4, pady=3)
                self._finding_cards.append(card)
            self._findings_scrollable_list.grid_columnconfigure(0, weight=1)
            # Scroll to top after populating
            self.after(50, lambda: self._findings_scrollable_list._parent_canvas.yview_moveto(0))
        self._update_severity_count_labels_in_sidebar(findings)

        # Update dashboard widgets
        if sr:
            sc = sr.severity_counts
            if sc:
                counts_dict = sc.to_dict()
                self._risk_meter.set_risk(sr.risk_score)
                self._stats_frame.update(
                    total=sr.total_findings,
                    critical=sc.critical,
                    high=sc.high,
                    files=sr.total_files,
                )

        # Update timeline and correlations
        finding_dicts = [f.to_dict() for f in findings]
        self._timeline_view.set_findings(finding_dicts)
        if sr and sr.correlations:
            self._correlation_view.set_events(sr.correlations)

        self._scan_progress_bar.set(1.0)
        self._scan_progress_percentage_label.configure(text="100%")
        self._scan_current_file_label.configure(text="")
        self._is_scan_running = False
        self._scan_action_button.configure(
            state="normal",
            text="Iniciar Scan",
            fg_color=ACCENT,
            text_color="white",
            hover_color=BTN_PRIMARY_HVR,
            command=self._start_scan_in_background_thread,
        )
        self._status_dot.configure(text_color=SUCCESS if total == 0 else ("#FF9500", "#FF9F0A"))
        counts_by_severity = {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in SEVERITY_SORT_PRIORITY
        }
        severity_summary = " \u00b7 ".join(
            f"{count} {sev}" for sev, count in counts_by_severity.items() if count > 0
        ) or "nenhum"

        self._update_status_bar_message(
            f"Scan conclu\u00eddo \u2014 {total} achado(s): {severity_summary}"
        )

    def _on_finding_card_click(self, finding: DetectionFinding):
        for card in getattr(self, "_finding_cards", []):
            try:
                is_this = card.finding is finding
                card.set_selected(is_this)
                if is_this:
                    self._selected_card = card
            except Exception:
                pass
        self._display_selected_finding_detail(finding)

    def _display_selected_finding_detail(self, finding: DetectionFinding):
        self._current_finding = finding
        self._detail_tabview.set("Detalhe")

        icon = SEVERITY_ICON[finding.severity]
        line_info = f"  Line        {finding.line}" if finding.line else ""
        mitre_info = f"  MITRE       {finding.mitre_technique}" if finding.mitre_technique else ""
        score_info = f"  Score       {round(finding.score, 1)}/100"
        detail_lines = [
            f"{icon}  [{finding.severity}]  {score_info.strip()}",
            "",
            f"  File        {finding.file_path}",
        ]
        if line_info:
            detail_lines.append(line_info)
        if mitre_info:
            detail_lines.append(mitre_info)
        detail_lines += [
            f"  Category    {finding.category}",
            "",
            f"  {finding.description}",
            "",
            "\u2500" * 48,
            "Evidence",
            "\u2500" * 48,
            "",
            finding.evidence or "(sem evid\u00eancia)",
        ]
        if finding.detected_terms:
            detail_lines += [
                "",
                "\u2500" * 48,
                "Detected Terms",
                "\u2500" * 48,
                "",
                ", ".join(finding.detected_terms),
            ]
        if finding.recommendation:
            detail_lines += [
                "",
                "\u2500" * 48,
                "Recommendation",
                "\u2500" * 48,
                "",
                finding.recommendation,
            ]
        self._finding_detail_textbox.configure(state="normal")
        self._finding_detail_textbox.delete("1.0", "end")
        self._finding_detail_textbox.insert("1.0", "\n".join(detail_lines))
        self._finding_detail_textbox.configure(state="disabled")

    def _show_info_menu(self):
        menu = ctk.CTkToplevel(self)
        menu.title("")
        menu.geometry("160x180+0+0")
        menu.transient(self)
        menu.grab_set()
        menu.overrideredirect(True)
        x = min(self.winfo_x() + self.winfo_width() - 190, self.winfo_screenwidth() - 170)
        y = min(self.winfo_y() + 80, self.winfo_screenheight() - 200)
        menu.geometry(f"160x180+{x}+{y}")
        menu.configure(fg_color=SURFACE)
        for text, cmd in (
            ("Configuracoes", self._open_settings),
            ("Sobre", self._show_about_dialog),
            ("Registro", self._show_changelog_dialog),
            ("Ajuda", self._show_help_dialog),
        ):
            btn = ctk.CTkButton(
                menu,
                text=text,
                width=140,
                height=34,
                font=ctk.CTkFont(size=13),
                fg_color="transparent",
                text_color=TEXT,
                hover_color=SURFACE2,
                anchor="w",
                command=lambda t=text, c=cmd: (menu.destroy(), c()),
            )
            btn.pack(padx=10, pady=2, fill="x")
        menu.focus_set()
        menu.bind("<FocusOut>", lambda _: menu.destroy())

    def _update_severity_count_labels_in_sidebar(self, findings: list[DetectionFinding]):
        counts = Counter(f.severity for f in findings)
        for severity, count_label in self._severity_count_labels.items():
            count_label.configure(text=str(counts.get(severity, 0)))

    def _clear_all_scan_results(self):
        self._remove_skeleton_loaders()
        self._all_findings = []
        self._finding_cards = []
        self._selected_card = None
        self._last_result = None
        self._current_finding = None
        self._findings_count_badge.configure(text="")
        for widget in self._findings_scrollable_list.winfo_children():
            widget.destroy()
        placeholder = ctk.CTkLabel(
            self._findings_scrollable_list,
            text="Nenhum scan realizado ainda.\nEscolha uma pasta e clique em Iniciar Scan.",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
            justify="center",
        )
        placeholder.grid(row=0, column=0, pady=50)
        self._finding_detail_textbox.configure(state="normal")
        self._finding_detail_textbox.delete("1.0", "end")
        self._finding_detail_textbox.configure(state="disabled")
        self._timeline_view.clear()
        self._correlation_view.clear()
        self._risk_meter.set_risk(0)
        self._stats_frame.update(0, 0, 0, 0)
        for count_label in self._severity_count_labels.values():
            count_label.configure(text="\u2014")
        self._scan_progress_bar.set(0)
        self._scan_progress_percentage_label.configure(text="")
        self._scan_current_file_label.configure(text="")
        self._status_dot.configure(text_color=SUCCESS)
        self._update_status_bar_message("Pronto. Selecione uma pasta e inicie o scan.")

    # ——— Info dialogs ———
    def _show_info_dialog(self, title: str, content: str, width: int = 580, height: int = 420):
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry(f"{width}x{height}")
        dialog.transient(self)
        dialog.grab_set()
        textbox = ctk.CTkTextbox(dialog, font=ctk.CTkFont(family="Menlo", size=12), wrap="word")
        textbox.pack(fill="both", expand=True, padx=12, pady=12)
        textbox.insert("1.0", content)
        textbox.configure(state="disabled")

    def _show_about_dialog(self):
        content = (
            "VSCode Security Scanner  v3.4.0\n"
            "\u2500" * 42 + "\n\n"
            "Detecta malware em projetos VSCode e vetores\n"
            "de ataque comuns em projetos clonados.\n\n"
            "Recursos:\n"
            "  \u2022 Varredura de tasks.json, settings.json\n"
            "  \u2022 Git hooks e npm lifecycle scripts\n"
            "  \u2022 Dockerfiles, Makefiles, pip config\n"
            "  \u2022 Cargo build scripts, Python build files\n"
            "  \u2022 Symlink escapes e ofusca\u00e7\u00e3o\n"
            "  \u2022 An\u00e1lise por entropia (base64/AES)\n\n"
            "Reposit\u00f3rio:\n"
            "  github.com/lucas/scanner\n"
            "\n"
            "Feito com Python, customtkinter e \u2764\n"
        )
        self._show_info_dialog("Sobre", content)

    def _show_changelog_dialog(self):
        content = (
            "Registro de Vers\u00f5es\n"
            "\u2500" * 42 + "\n\n"
            "v3.4.0\n"
            "  \u2022 Modo parar varredura (bot\u00e3o Parar)\n"
            "  \u2022 Di\u00e1logos Sobre / Registro / Ajuda\n"
            "  \u2022 Rolagem com trackpad no macOS\n"
            "  \u2022 Performance: redu\u00e7\u00e3o de ~30 travessias\n"
            "    de disco para 1 (\u00fanico os.walk)\n"
            "  \u2022 Thread-safety no progresso da GUI\n\n"
            "v3.3.0\n"
            "  \u2022 Detec\u00e7\u00e3o de .pth files (Python path injection)\n"
            "  \u2022 Bundler configs (Vite, Next.js, Webpack, Tailwind)\n"
            "  \u2022 mise.toml e .tool-versions\n"
            "  \u2022 Skeleton loaders animados\n"
            "  \u2022 Carga de regras externalizada (rules.toml)\n\n"
            "v3.2.0\n"
            "  \u2022 An\u00e1lise de ofusca\u00e7\u00e3o (homoglifos, join)\n"
            "  \u2022 Shannon entropy para detec\u00e7\u00e3o de base64\n"
            "  \u2022 AST parsing opcional (esprima)\n"
        )
        self._show_info_dialog("Registro de Vers\u00f5es", content, width=520, height=460)

    def _show_help_dialog(self):
        content = (
            "Ajuda \u2014 Como Usar\n"
            "\u2500" * 42 + "\n\n"
            "USO B\u00c1SICO\n"
            "  1. Selecione uma pasta com o bot\u00e3o Browse\n"
            "     ou cole o caminho manualmente\n"
            "  2. Ative \"Incluir ~/.vscode global\"\n"
            "     para escanear configura\u00e7\u00f5es globais\n"
            "  3. Clique em \"Iniciar Scan\"\n"
            "  4. Clique em \"\u23f9 Parar\" para interromper\n\n"
            "RESULTADOS\n"
            "  \u2022 Cards coloridos por severidade\n"
            "  \u2022 Clique em um card para ver detalhes\n"
            "  \u2022 Sidebar mostra contagem por severidade\n\n"
            "EXPORTAR\n"
            "  \u2022 Bot\u00e3o \"Exportar JSON\" no sidebar\n\n"
            "LINHA DE COMANDO\n"
            "  uv run python cli.py scan --path .\n"
            "  uv run python cli.py scan --path . --json report.json\n"
            "  uv run python cli.py scan --path . --no-global\n\n"
            "DIRET\u00d3RIOS IGNORADOS\n"
            "  node_modules, .venv, venv, env,\n"
            "  site-packages, __pycache__, .tox,\n"
            "  .eggs, dist, build, .mypy_cache,\n"
            "  .pytest_cache\n"
        )
        self._show_info_dialog("Ajuda", content, width=540, height=500)

    def _export_current_findings(self):
        if not self._last_result:
            messagebox.showinfo(
                "Sem dados",
                "Nenhum achado para exportar.\nRealize um scan primeiro.",
            )
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = filedialog.asksaveasfilename(
            title="Salvar relat\u00f3rio de seguran\u00e7a",
            defaultextension=".json",
            filetypes=[
                ("JSON", "*.json"),
                ("Markdown", "*.md"),
                ("HTML", "*.html"),
                ("PDF", "*.pdf"),
                ("Todos os arquivos", "*.*"),
            ],
            initialfile=f"security_report_{timestamp}.json",
        )
        if not output_path:
            return
        p = Path(output_path)
        ext = p.suffix.lower()
        try:
            if ext == ".json":
                JSONReport().save(self._last_result, p)
            elif ext == ".md":
                MarkdownReport().save(self._last_result, p)
            elif ext == ".html":
                HTMLReport().save(self._last_result, p)
            elif ext == ".pdf":
                PDFReport().save(self._last_result, p)
            else:
                JSONReport().save(self._last_result, p)
            self._update_status_bar_message(f"Relat\u00f3rio exportado: {output_path}")
            messagebox.showinfo("Relat\u00f3rio salvo", f"Arquivo salvo em:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar relat\u00f3rio:\n{e}")

    def _open_ioc_inspector(self):
        if not self._all_findings:
            messagebox.showinfo("Sem dados", "Realize um scan primeiro.")
            return
        IOCInspectorDialog(self, self._all_findings)

    def _open_file_inspector(self):
        if not self._current_finding:
            messagebox.showinfo("Sem seleção", "Selecione um achado primeiro.")
            return
        fp = self._current_finding.file_path
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = "(erro ao ler arquivo)"
        FileInspectorDialog(self, fp, content, [self._current_finding.to_dict()])

    def _open_settings(self):
        settings = {
            "project": True,
            "git": True,
            "docker": True,
            "env": True,
            "yaml": True,
            "global_vscode": True,
            "export_format": "json",
        }
        SettingsDialog(self, settings, on_save=self._on_settings_save)

    def _on_settings_save(self, settings: dict) -> None:
        self._should_scan_global_vscode.set(
            settings.get("global_vscode", True)
        )

    def _update_status_bar_message(self, message: str):
        self.after(0, lambda: self._status_message_label.configure(text=message))
