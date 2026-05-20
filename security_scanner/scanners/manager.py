from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Optional

from security_scanner.correlation import CorrelationEngine
from security_scanner.models import DetectionFinding, ScanResult, SeverityCounts
from security_scanner.scanners.base import BaseScanner
from security_scanner.scanners.project_scanner import ProjectScanner
from security_scanner.scanners.global_vscode_scanner import GlobalVSCodeScanner
from security_scanner.scanners.git_scanner import GitScanner
from security_scanner.scanners.docker_scanner import DockerScanner
from security_scanner.scanners.env_scanner import EnvScanner
from security_scanner.scanners.yaml_scanner import YAMLScanner

EXCLUDED_DIRS = {
    ".venv", "venv", "env", "node_modules", "site-packages",
    "__pycache__", ".tox", ".eggs", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".git", ".svn", ".hg",
}


class ScannerManager:
    def __init__(self, excluded_dirs: Optional[set[str]] = None):
        self._scanners: list[BaseScanner] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._excluded_dirs = excluded_dirs or EXCLUDED_DIRS
        self.correlation = CorrelationEngine()
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(ProjectScanner())
        self.register(GitScanner())
        self.register(DockerScanner())
        self.register(EnvScanner())
        self.register(YAMLScanner())

    def register(self, scanner: BaseScanner) -> None:
        with self._lock:
            self._scanners.append(scanner)

    def stop(self) -> None:
        self._stop_event.set()

    def reset_stop(self) -> None:
        self._stop_event.clear()

    @property
    def scanners(self) -> list[BaseScanner]:
        with self._lock:
            return list(self._scanners)

    def _should_skip(self, file_path: Path) -> bool:
        for part in file_path.parts:
            if part in self._excluded_dirs:
                return True
        return False

    def scan_path(
        self,
        path: Path,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        include_global: bool = False,
    ) -> ScanResult:
        self.reset_stop()
        start = time.time()
        all_findings: list[DetectionFinding] = []
        total_files = 0

        if include_global:
            global_files = GlobalVSCodeScanner.get_global_files()
            total_files += len(global_files)
            gs = GlobalVSCodeScanner()
            processed = 0
            for fp in global_files:
                if self._stop_event.is_set():
                    break
                try:
                    content = gs.read_file_safe(fp)
                    findings = gs.scan(fp, content)
                    if findings:
                        all_findings.extend(findings)
                except Exception:
                    pass
                processed += 1
                if progress_callback:
                    progress_callback("~/.vscode/", processed, total_files)

        if path.is_file():
            files_to_scan = [path]
        else:
            files_to_scan = list(path.rglob("*"))

        project_files = [f for f in files_to_scan if f.is_file() and not self._should_skip(f)]
        total_files += len(project_files)

        processed = 0
        for fp in project_files:
            if self._stop_event.is_set():
                break
            try:
                scanner = self._pick_scanner(fp)
                if scanner is None:
                    processed += 1
                    continue
                content = scanner.read_file_safe(fp)
                findings = scanner.scan(fp, content)
                if findings:
                    all_findings.extend(findings)
            except Exception:
                pass
            processed += 1
            if progress_callback and processed % 10 == 0:
                progress_callback(str(path), processed, total_files)

        duration_ms = int((time.time() - start) * 1000)
        result = ScanResult(
            target=path,
            duration_ms=duration_ms,
            total_files=total_files,
            findings=all_findings,
            severity_counts=SeverityCounts.from_findings(all_findings),
        )
        self.correlation.correlate_scan(result)
        return result

    def _pick_scanner(self, file_path: Path) -> Optional[BaseScanner]:
        for scanner in self._scanners:
            if not scanner.enabled:
                continue
            try:
                if scanner.can_handle(file_path):
                    return scanner
            except Exception:
                continue
        return None
