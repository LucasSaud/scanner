from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScanEvent:
    event_type: str
    timestamp: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
        }


@dataclass
class ScanStarted(ScanEvent):
    def __init__(self, path: Path, scan_id: str, options: Optional[dict] = None):
        super().__init__(
            event_type="scan_started",
            data={
                "path": str(path),
                "scan_id": scan_id,
                "options": options or {},
            },
        )


@dataclass
class FileScanned(ScanEvent):
    def __init__(self, file_path: Path, scanner_name: str, duration_ms: int,
                 finding_count: int):
        super().__init__(
            event_type="file_scanned",
            data={
                "file_path": str(file_path),
                "scanner": scanner_name,
                "duration_ms": duration_ms,
                "finding_count": finding_count,
            },
        )


@dataclass
class FindingDetected(ScanEvent):
    def __init__(self, finding_id: str, severity: str, category: str,
                 file_path: Path):
        super().__init__(
            event_type="finding_detected",
            data={
                "finding_id": finding_id,
                "severity": severity,
                "category": category,
                "file_path": str(file_path),
            },
        )


@dataclass
class ScanCompleted(ScanEvent):
    def __init__(self, scan_id: str, duration_ms: int, total_files: int,
                 total_findings: int, risk_score: float):
        super().__init__(
            event_type="scan_completed",
            data={
                "scan_id": scan_id,
                "duration_ms": duration_ms,
                "total_files": total_files,
                "total_findings": total_findings,
                "risk_score": round(risk_score, 1),
            },
        )


@dataclass
class CorrelationMatch(ScanEvent):
    def __init__(self, rule_id: str, name: str, severity: str, score: float,
                 finding_ids: list[str]):
        super().__init__(
            event_type="correlation_match",
            data={
                "rule_id": rule_id,
                "name": name,
                "severity": severity,
                "score": round(score, 1),
                "finding_ids": finding_ids,
            },
        )
