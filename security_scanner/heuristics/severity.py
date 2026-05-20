from __future__ import annotations

from typing import Optional

from security_scanner.models.finding import SEVERITY_SCORE_RANGES, SEVERITY_VALUES


class SeverityClassifier:
    @staticmethod
    def from_score(score: float) -> str:
        for sev in reversed(SEVERITY_VALUES):
            lo, hi = SEVERITY_SCORE_RANGES[sev]
            if lo <= score <= hi:
                return sev
        return "INFO"

    @staticmethod
    def from_signal_count(count: int) -> str:
        if count >= 5:
            return "CRITICAL"
        if count >= 3:
            return "HIGH"
        if count >= 2:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def combine(a: str, b: str) -> str:
        rank = {s: i for i, s in enumerate(SEVERITY_VALUES)}
        return a if rank.get(a, 0) >= rank.get(b, 0) else b

    @staticmethod
    def requires_attention(severity: str) -> bool:
        return severity in ("HIGH", "CRITICAL")

    @staticmethod
    def color(severity: str) -> str:
        return {
            "CRITICAL": "#FF3B30",
            "HIGH": "#FF9500",
            "MEDIUM": "#FFCC00",
            "LOW": "#8E8E93",
            "INFO": "#5AC8FA",
        }.get(severity, "#8E8E93")
