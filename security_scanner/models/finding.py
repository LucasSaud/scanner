from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SEVERITY_VALUES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_SORT_PRIORITY: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

SEVERITY_BADGE_BG_COLOR: dict[str, str] = {
    "CRITICAL": "#FF3B30",
    "HIGH": "#FF9500",
    "MEDIUM": "#FFCC00",
    "LOW": "#8E8E93",
    "INFO": "#5AC8FA",
}

SEVERITY_BADGE_TEXT_COLOR: dict[str, str] = {
    "CRITICAL": "white",
    "HIGH": "white",
    "MEDIUM": "#1c1c1e",
    "LOW": "white",
    "INFO": "#1c1c1e",
}

SEVERITY_ICON: dict[str, str] = {
    "CRITICAL": "\u25C6",
    "HIGH": "\u25B2",
    "MEDIUM": "\u25CF",
    "LOW": "\u25CB",
    "INFO": "\u2139",
}

SEVERITY_STRIP_COLOR: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#FF3B30", "#FF453A"),
    "HIGH": ("#FF9500", "#FF9F0A"),
    "MEDIUM": ("#FFCC00", "#FFD60A"),
    "LOW": ("#8E8E93", "#AEAEB2"),
    "INFO": ("#5AC8FA", "#64D2FF"),
}

SEVERITY_SCORE_RANGES: dict[str, tuple[float, float]] = {
    "INFO": (0.0, 19.0),
    "LOW": (20.0, 39.0),
    "MEDIUM": (40.0, 59.0),
    "HIGH": (60.0, 84.0),
    "CRITICAL": (85.0, 100.0),
}


def severity_from_score(score: float) -> str:
    for sev, (lo, hi) in SEVERITY_SCORE_RANGES.items():
        if lo <= score <= hi:
            return sev
    return "INFO"


def generate_finding_id(category: str, index: int) -> str:
    prefix = {"supply_chain": "SC", "ide_poisoning": "ID", "persistence": "PE",
              "exfiltration": "EX", "command_injection": "CI", "backdoor": "BD",
              "container_escape": "CE", "ci_cd_abuse": "CD", "general": "GN"}.get(category, "GN")
    return f"{prefix}-{index:03d}"


@dataclass
class DetectionFinding:
    id: str = ""
    title: str = ""
    severity: str = "MEDIUM"
    score: float = 50.0
    file_path: Path = Path()
    line: Optional[int] = None
    evidence: str = ""
    category: str = "general"
    description: str = ""
    recommendation: str = ""
    detected_terms: list[str] = field(default_factory=list)
    risk_vector: list[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    correlation_id: Optional[str] = None
    raw_context: Optional[str] = None
    suggestion: Optional[str] = None
    line_number: Optional[int] = None
    risk_score: Optional[float] = None

    def __post_init__(self):
        if not self.id:
            raw = f"{self.file_path}:{self.line or 0}:{self.description}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]
        if not self.title and self.description:
            self.title = self.description[:80]
        if self.line_number is not None and self.line is None:
            self.line = self.line_number
        if self.risk_score is not None and self.score == 50.0:
            self.score = self.risk_score * 10.0
        if self.suggestion and not self.recommendation:
            self.recommendation = self.suggestion

    @property
    def severity_rank(self) -> int:
        return SEVERITY_SORT_PRIORITY.get(self.severity, 9)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "score": round(self.score, 1),
            "file": str(self.file_path),
            "line": self.line,
            "evidence": self.evidence,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "detected_terms": self.detected_terms,
            "risk_vector": self.risk_vector,
            "mitre_technique": self.mitre_technique,
            "correlation_id": self.correlation_id,
        }
