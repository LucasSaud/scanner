from __future__ import annotations

import os
import threading
import time
import uuid
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
from security_scanner.telemetry import telemetry_logger, scan_metrics, ScanStarted, ScanCompleted
from security_scanner.cache import scan_cache
from security_scanner.utils.hash_utils import file_hash, text_hash

EXCLUDED_DIRS = {
    ".venv", "venv", "env", "node_modules", "site-packages",
    "__pycache__", ".tox", ".eggs", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".git", ".svn", ".hg",
}

_KNOWN_FILENAMES = {
    "dockerfile", "makefile", "gemfile", "vagrantfile",
    ".gitignore", ".gitattributes",
}


class ScannerManager:
    def __init__(self, excluded_dirs: Optional[set[str]] = None):
        self._scanners: list[BaseScanner] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._excluded_dirs = excluded_dirs or EXCLUDED_DIRS
        self._supported_extensions: set[str] = set()
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
            self._supported_extensions.update(scanner.supported_extensions)

    def stop(self) -> None:
        self._stop_event.set()

    def reset_stop(self) -> None:
        self._stop_event.clear()

    @property
    def scanners(self) -> list[BaseScanner]:
        with self._lock:
            return list(self._scanners)

    def _is_supported(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        if ext in self._supported_extensions:
            return True
        name = file_path.name.lower()
        if name in _KNOWN_FILENAMES:
            return True
        for se in self._supported_extensions:
            if name.endswith(se):
                return True
        return False

    def scan_path(
        self,
        path: Path,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        include_global: bool = False,
        use_cache: bool = False,
    ) -> ScanResult:
        self.reset_stop()
        scan_id = str(uuid.uuid4())[:8]
        start = time.time()
        all_findings: list[DetectionFinding] = []
        total_files = 0
        cache_hits = 0

        telemetry_logger.info("scan_started", scan_id=scan_id, path=str(path))

        if include_global:
            global_files = GlobalVSCodeScanner.get_global_files()
            total_files += len(global_files)
            gs = GlobalVSCodeScanner()
            processed = 0
            for fp in global_files:
                if self._stop_event.is_set():
                    break
                try:
                    if use_cache and scan_cache.is_cached(fp):
                        cache_hits += 1
                        processed += 1
                        continue
                    content = gs.read_file_safe(fp)
                    findings = gs.scan(fp, content)
                    if findings:
                        all_findings.extend(findings)
                    if use_cache and content:
                        try:
                            stat = fp.stat()
                            chash = file_hash(fp) or ""
                            fhash = text_hash(str([f.to_dict() for f in findings]))
                            scan_cache.mark_cached(fp, stat.st_mtime, chash, fhash)
                        except Exception:
                            pass
                except Exception as e:
                    telemetry_logger.debug("scanner_error", file=str(fp), error=str(e))
                processed += 1
                if progress_callback:
                    progress_callback(str(fp), processed, total_files)

        project_files: list[Path] = []
        if path.is_file():
            project_files = [path]
        else:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in self._excluded_dirs]
                for f in files:
                    fp = Path(root, f)
                    if fp.name.startswith(".") and not fp.name.startswith(".."):
                        pass
                    project_files.append(fp)

        total_files += len(project_files)

        processed = 0
        for fp in project_files:
            if self._stop_event.is_set():
                break
            if use_cache and scan_cache.is_cached(fp):
                cache_hits += 1
                processed += 1
                continue
            if not self._is_supported(fp):
                processed += 1
                continue
            try:
                scanner = self._pick_scanner(fp)
                if scanner is None:
                    processed += 1
                    continue
                content = scanner.read_file_safe(fp)
                findings = scanner.scan(fp, content)
                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        scan_metrics.record_finding(f.severity, f.category)
                if use_cache and content:
                    try:
                        stat = fp.stat()
                        chash = file_hash(fp) or ""
                        fhash = text_hash(str([f.to_dict() for f in findings]))
                        scan_cache.mark_cached(fp, stat.st_mtime, chash, fhash)
                    except Exception:
                        pass
            except Exception as e:
                telemetry_logger.debug("scanner_error", file=str(fp), error=str(e))
            processed += 1
            if progress_callback:
                progress_callback(str(fp), processed, total_files)

        if use_cache:
            scan_cache.flush()

        duration_ms = int((time.time() - start) * 1000)
        result = ScanResult(
            target=path,
            duration_ms=duration_ms,
            total_files=total_files - cache_hits,
            findings=all_findings,
            severity_counts=SeverityCounts.from_findings(all_findings),
        )
        self.correlation.correlate_scan(result)

        scan_metrics.record_scan(
            files=total_files,
            findings=len(all_findings),
            correlations=len(result.correlations),
            duration_ms=duration_ms,
        )
        telemetry_logger.info("scan_completed",
            scan_id=scan_id, duration_ms=duration_ms, findings=len(all_findings))

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
