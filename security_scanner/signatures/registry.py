from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class SignatureMatch:
    signature_id: str
    name: str
    severity: str
    score: float
    matched: str
    category: str = "general"
    description: str = ""
    recommendation: str = ""


class SignatureRegistry:
    def __init__(self):
        self._regex_signatures: list[dict] = []
        self._ioc_signatures: list[dict] = []
        self._command_signatures: list[dict] = []
        self._compiled: dict[str, re.Pattern] = {}

    def register_regex(self, sig_id: str, pattern: str, severity: str = "MEDIUM",
                       score: float = 50.0, category: str = "general",
                       description: str = "", recommendation: str = "",
                       flags: int = re.IGNORECASE) -> None:
        compiled = re.compile(pattern, flags)
        self._compiled[sig_id] = compiled
        self._regex_signatures.append({
            "id": sig_id, "pattern": pattern, "compiled": compiled,
            "severity": severity, "score": score, "category": category,
            "description": description, "recommendation": recommendation,
        })

    def register_ioc(self, sig_id: str, value: str, severity: str = "MEDIUM",
                     score: float = 50.0, category: str = "ioc") -> None:
        self._ioc_signatures.append({
            "id": sig_id, "value": value, "severity": severity,
            "score": score, "category": category,
        })

    def register_command(self, sig_id: str, command: str, severity: str = "HIGH",
                         score: float = 70.0, category: str = "command") -> None:
        self._command_signatures.append({
            "id": sig_id, "command": command, "severity": severity,
            "score": score, "category": category,
        })

    def match_all(self, text: str, filename: str = "") -> list[SignatureMatch]:
        matches: list[SignatureMatch] = []
        text_lower = text.lower()

        for sig in self._regex_signatures:
            try:
                if sig["compiled"].search(text):
                    matches.append(SignatureMatch(
                        signature_id=sig["id"],
                        name=sig["id"],
                        severity=sig["severity"],
                        score=sig["score"],
                        matched=text[:200],
                        category=sig["category"],
                        description=sig["description"],
                        recommendation=sig["recommendation"],
                    ))
            except Exception:
                pass

        for sig in self._command_signatures:
            if sig["command"].lower() in text_lower:
                matches.append(SignatureMatch(
                    signature_id=sig["id"],
                    name=sig["id"],
                    severity=sig["severity"],
                    score=sig["score"],
                    matched=text[:200],
                    category=sig["category"],
                ))

        return matches

    def match_file(self, content: str, filename: str) -> list[SignatureMatch]:
        return self.match_all(content, filename)

    def count(self) -> dict[str, int]:
        return {
            "regex": len(self._regex_signatures),
            "ioc": len(self._ioc_signatures),
            "command": len(self._command_signatures),
        }
