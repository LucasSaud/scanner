from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CorrelationEvent:
    id: str
    name: str
    severity: str
    score: float
    description: str
    rule_id: str
    finding_ids: list[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "score": round(self.score, 1),
            "description": self.description,
            "rule_id": self.rule_id,
            "finding_ids": self.finding_ids,
            "mitre_technique": self.mitre_technique,
            "recommendation": self.recommendation,
        }
