from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from security_scanner.models.finding import SEVERITY_SCORE_RANGES, severity_from_score


class ScoreModifier(Enum):
    ENTROPY_HIGH = ("entropy_high", 10.0)
    ENTROPY_VERY_HIGH = ("entropy_very_high", 20.0)
    OBFUSCATION = ("obfuscation", 15.0)
    AUTO_EXECUTION = ("auto_execution", 20.0)
    NETWORK_ACCESS = ("network_access", 15.0)
    PERSISTENCE = ("persistence", 20.0)
    PRIVILEGE_ESCALATION = ("privilege_escalation", 25.0)
    SUPPLY_CHAIN = ("supply_chain", 20.0)
    MULTIPLE_SIGNALS = ("multiple_signals", 15.0)
    CORRELATED_FINDING = ("correlated_finding", 10.0)
    REMOTE_DOWNLOAD = ("remote_download", 15.0)
    SHELL_EXECUTION = ("shell_execution", 15.0)
    HIDDEN_OPERATION = ("hidden_operation", 10.0)
    SENSITIVE_FILE_ACCESS = ("sensitive_file_access", 20.0)


@dataclass
class RiskScorer:
    base_score: float = 50.0
    modifiers: list[tuple[ScoreModifier, float]] = field(default_factory=list)
    _final_score: Optional[float] = None

    def add_modifier(self, modifier: ScoreModifier, multiplier: float = 1.0) -> RiskScorer:
        self.modifiers.append((modifier, multiplier))
        return self

    def calculate(self) -> float:
        score = self.base_score
        for modifier, multiplier in self.modifiers:
            score += modifier.value[1] * multiplier
        score = max(0.0, min(100.0, score))
        self._final_score = score
        return score

    @property
    def severity(self) -> str:
        return severity_from_score(self.calculate())

    @property
    def final_score(self) -> float:
        if self._final_score is None:
            self.calculate()
        return self._final_score or self.base_score

    def to_dict(self) -> dict:
        return {
            "base_score": self.base_score,
            "modifiers": [{"name": m.value[0], "value": m.value[1] * mult}
                          for m, mult in self.modifiers],
            "final_score": round(self.final_score, 1),
            "severity": self.severity,
        }

    @classmethod
    def from_finding_characteristics(cls, has_auto_exec: bool = False,
                                     has_network: bool = False,
                                     has_persistence: bool = False,
                                     has_obfuscation: bool = False,
                                     has_shell_exec: bool = False,
                                     has_remote_download: bool = False,
                                     has_privilege_esc: bool = False,
                                     has_supply_chain: bool = False,
                                     has_sensitive_file: bool = False,
                                     entropy_value: float = 0.0,
                                     signal_count: int = 1) -> RiskScorer:
        scorer = cls(base_score=30.0)
        if has_auto_exec:
            scorer.add_modifier(ScoreModifier.AUTO_EXECUTION)
        if has_network:
            scorer.add_modifier(ScoreModifier.NETWORK_ACCESS)
        if has_persistence:
            scorer.add_modifier(ScoreModifier.PERSISTENCE)
        if has_obfuscation:
            scorer.add_modifier(ScoreModifier.OBFUSCATION)
        if has_shell_exec:
            scorer.add_modifier(ScoreModifier.SHELL_EXECUTION)
        if has_remote_download:
            scorer.add_modifier(ScoreModifier.REMOTE_DOWNLOAD)
        if has_privilege_esc:
            scorer.add_modifier(ScoreModifier.PRIVILEGE_ESCALATION)
        if has_supply_chain:
            scorer.add_modifier(ScoreModifier.SUPPLY_CHAIN)
        if has_sensitive_file:
            scorer.add_modifier(ScoreModifier.SENSITIVE_FILE_ACCESS)
        if signal_count > 2:
            scorer.add_modifier(ScoreModifier.MULTIPLE_SIGNALS,
                                multiplier=min(1.5, 0.5 * (signal_count - 1)))
        if entropy_value > 6.0:
            scorer.add_modifier(ScoreModifier.ENTROPY_VERY_HIGH)
        elif entropy_value > 4.5:
            scorer.add_modifier(ScoreModifier.ENTROPY_HIGH)
        return scorer
