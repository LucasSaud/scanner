from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from security_scanner.config import _RULES_PATH, _load_rules


@dataclass
class RuleOverride:
    category: str
    pattern: str
    label: str
    score: float = 0.0
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


class RulesLoader:
    def __init__(self, rules_path: Optional[Path] = None):
        self._path = rules_path or _RULES_PATH
        self._rules: dict = {}
        self._overrides: dict[str, list[RuleOverride]] = {}
        self.reload()

    def reload(self) -> None:
        self._rules = _load_rules()
        self._parse_overrides()

    def _parse_overrides(self) -> None:
        self._overrides.clear()
        for section, value in self._rules.items():
            if not section.startswith("detector."):
                continue
            category = section.split(".", 1)[1]
            overrides: list[RuleOverride] = []
            raw_list = value if isinstance(value, list) else []
            for entry in raw_list:
                if isinstance(entry, dict):
                    overrides.append(RuleOverride(
                        category=category,
                        pattern=str(entry.get("pattern", "")),
                        label=str(entry.get("label", "")),
                        score=float(entry.get("score", 0.0)),
                        enabled=bool(entry.get("enabled", True)),
                        metadata={k: v for k, v in entry.items()
                                  if k not in ("pattern", "label", "score", "enabled")},
                    ))
            if overrides:
                self._overrides[category] = overrides

    def get_overrides(self, category: str) -> list[RuleOverride]:
        return self._overrides.get(category, [])

    def get_patterns_for(self, category: str) -> list[str]:
        return [o.pattern for o in self.get_overrides(category) if o.enabled]

    @property
    def all_categories(self) -> list[str]:
        return list(self._overrides.keys())


rules_loader = RulesLoader()
