from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanMetrics:
    total_scans: int = 0
    total_files: int = 0
    total_findings: int = 0
    total_correlations: int = 0
    total_duration_ms: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    start_time: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_scan(self, files: int, findings: int, correlations: int,
                    duration_ms: int) -> None:
        with self._lock:
            self.total_scans += 1
            self.total_files += files
            self.total_findings += findings
            self.total_correlations += correlations
            self.total_duration_ms += duration_ms

    def record_finding(self, severity: str, category: str) -> None:
        with self._lock:
            self.findings_by_severity[severity] = self.findings_by_severity.get(severity, 0) + 1
            self.findings_by_category[category] = self.findings_by_category.get(category, 0) + 1

    @property
    def avg_duration_ms(self) -> float:
        if self.total_scans == 0:
            return 0.0
        return self.total_duration_ms / self.total_scans

    @property
    def uptime_seconds(self) -> float:
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time

    def reset(self) -> None:
        with self._lock:
            self.total_scans = 0
            self.total_files = 0
            self.total_findings = 0
            self.total_correlations = 0
            self.total_duration_ms = 0
            self.findings_by_severity.clear()
            self.findings_by_category.clear()

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "total_scans": self.total_scans,
                "total_files": self.total_files,
                "total_findings": self.total_findings,
                "total_correlations": self.total_correlations,
                "total_duration_ms": self.total_duration_ms,
                "avg_duration_ms": round(self.avg_duration_ms, 1),
                "findings_by_severity": dict(self.findings_by_severity),
                "findings_by_category": dict(self.findings_by_category),
                "uptime_seconds": round(self.uptime_seconds, 1),
            }


scan_metrics = ScanMetrics(start_time=time.time())
