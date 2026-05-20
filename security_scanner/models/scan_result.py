from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from security_scanner.models.finding import DetectionFinding, SEVERITY_VALUES


@dataclass
class SeverityCounts:
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "INFO": self.info,
            "LOW": self.low,
            "MEDIUM": self.medium,
            "HIGH": self.high,
            "CRITICAL": self.critical,
        }

    @classmethod
    def from_findings(cls, findings: list[DetectionFinding]) -> SeverityCounts:
        counts = cls()
        for f in findings:
            key = f.severity.lower()
            if hasattr(counts, key):
                setattr(counts, key, getattr(counts, key) + 1)
        return counts


@dataclass
class ScanResult:
    scan_id: str = ""
    timestamp: str = ""
    target: Path = Path()
    duration_ms: int = 0
    total_files: int = 0
    total_findings: int = 0
    severity_counts: Optional[SeverityCounts] = None
    findings: list[DetectionFinding] = field(default_factory=list)
    correlations: list[dict] = field(default_factory=list)
    risk_score: float = 0.0
    excluded_dirs: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = str(uuid.uuid4())[:8]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.severity_counts is None:
            self.severity_counts = SeverityCounts.from_findings(self.findings) if self.findings else SeverityCounts()
        self.total_findings = len(self.findings)
        if self.findings:
            self.risk_score = max(f.score for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target": str(self.target),
            "duration_ms": self.duration_ms,
            "total_files": self.total_files,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts.to_dict(),
            "risk_score": round(self.risk_score, 1),
            "correlations": self.correlations,
            "findings": [f.to_dict() for f in self.findings],
        }
