from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from security_scanner.models import DetectionFinding, CorrelationEvent, ScanResult


@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    severity: str
    base_score: float
    mitre_technique: Optional[str] = None
    recommendation: str = ""
    relevant_categories: set[str] = field(default_factory=set)
    condition_fn: Callable[[list[DetectionFinding]], bool] = lambda f: False
    score_fn: Callable[[list[DetectionFinding]], float] = lambda f: 0.0

    def evaluate(self, findings: list[DetectionFinding]) -> Optional[CorrelationEvent]:
        if self.relevant_categories:
            matching = [f for f in findings if f.category in self.relevant_categories]
        else:
            matching = findings
        if not matching:
            return None
        if self.condition_fn(matching):
            score = self.score_fn(matching) or self.base_score
            return CorrelationEvent(
                id=f"CORR-{uuid.uuid4().hex[:8]}",
                name=self.name,
                severity=self.severity,
                score=min(score, 100.0),
                description=self.description,
                rule_id=self.rule_id,
                finding_ids=[f.id for f in matching],
                mitre_technique=self.mitre_technique,
                recommendation=self.recommendation,
            )
        return None


def _has_categories(findings: list[DetectionFinding], *cats: str) -> bool:
    return any(f.category in cats for f in findings)


def _count_categories(findings: list[DetectionFinding], *cats: str) -> int:
    return sum(1 for f in findings if f.category in cats)


def _has_term_in_any(fs: list[DetectionFinding], *terms: str) -> bool:
    lower = " ".join(f.evidence.lower() + f.description.lower() for f in fs)
    return any(t in lower for t in terms)


BUILTIN_RULES: list[CorrelationRule] = [
    CorrelationRule(
        rule_id="CORR-001",
        name="IDE Poisoning Chain",
        severity="CRITICAL",
        base_score=95.0,
        description="tasks.json auto-exec + package.json postinstall + settings.json URL externa — cadeia completa de envenenamento de IDE.",
        mitre_technique="T1554.001",
        recommendation="Remova as tasks suspeitas, limpe o package.json e audite alteracoes no .vscode/.",
        relevant_categories={"ide_poisoning", "supply_chain"},
        condition_fn=lambda fs: (
            _has_categories(fs, "ide_poisoning") and
            _has_categories(fs, "supply_chain") and
            _has_term_in_any(fs, "tasks.json", "settings.json", "postinstall", "preinstall")
        ),
        score_fn=lambda fs: 95.0 + 5.0 * min(3, len(fs)),
    ),
    CorrelationRule(
        rule_id="CORR-002",
        name="Persistence Triad",
        severity="HIGH",
        base_score=90.0,
        description="Git hook + cron + systemd — trindade de persistencia detectada.",
        mitre_technique="T1543.002",
        recommendation="Revise hooks, crontabs e units do systemd. Remova entradas nao autorizadas.",
        relevant_categories={"persistence"},
        condition_fn=lambda fs: len(fs) >= 2,
        score_fn=lambda fs: 85.0 + 5.0 * min(3, len(fs)),
    ),
    CorrelationRule(
        rule_id="CORR-003",
        name="Supply Chain Infection",
        severity="CRITICAL",
        base_score=95.0,
        description="Pacote typosquatting + extra index URL + script preinstall — infeccao de supply chain.",
        mitre_technique="T1195.001",
        recommendation="Remova o pacote suspeito, verifique lockfiles e altere tokens de acesso.",
        relevant_categories={"supply_chain"},
        condition_fn=lambda fs: len(fs) >= 3,
        score_fn=lambda fs: 90.0 + 5.0 * min(2, len(fs) - 2),
    ),
    CorrelationRule(
        rule_id="CORR-004",
        name="Container Escape Pattern",
        severity="CRITICAL",
        base_score=95.0,
        description="Docker socket mount + privileged mode + host network — fuga de container completa.",
        mitre_technique="T1611",
        recommendation="Evite montar /var/run/docker.sock em containers. Use capabilites minimas e rede none.",
        relevant_categories={"container_escape"},
        condition_fn=lambda fs: len(fs) >= 2,
        score_fn=lambda fs: 90.0 + 5.0 * min(2, len(fs) - 1),
    ),
    CorrelationRule(
        rule_id="CORR-005",
        name="Exfiltration Pipeline",
        severity="HIGH",
        base_score=85.0,
        description="Dump de env vars + URL de webhook + decode base64 — pipeline de exfiltracao.",
        mitre_technique="T1041",
        recommendation="Nunca armazene secrets em .env no repositorio. Audite logs de rede.",
        relevant_categories={"exfiltration"},
        condition_fn=lambda fs: len(fs) >= 2,
        score_fn=lambda fs: 80.0 + 5.0 * min(2, len(fs) - 1),
    ),
    CorrelationRule(
        rule_id="CORR-006",
        name="Backdoor + Persistence",
        severity="CRITICAL",
        base_score=95.0,
        description="Reverse shell + alteracao de SSH/chave + cron — backdoor com persistencia.",
        mitre_technique="T1078.003",
        recommendation="Revise authorized_keys, cron jobs e conexoes de rede ativas. Rode um antivirus.",
        relevant_categories={"backdoor", "persistence"},
        condition_fn=lambda fs: (
            _has_categories(fs, "backdoor") and
            _has_categories(fs, "persistence")
        ),
        score_fn=lambda fs: 92.0 + 3.0 * min(3, len(fs)),
    ),
    CorrelationRule(
        rule_id="CORR-007",
        name="CI/CD Abuse",
        severity="HIGH",
        base_score=85.0,
        description="Github Action com pipe-to-shell + comando unpinned + base64 — pipeline CI/CD comprometido.",
        mitre_technique="T1195.002",
        recommendation="Pine actions por hash. Nunca pipe para shell. Audite logs de CI.",
        relevant_categories={"ci_cd_abuse"},
        condition_fn=lambda fs: len(fs) >= 2,
        score_fn=lambda fs: 80.0 + 5.0 * min(2, len(fs) - 1),
    ),
]


class CorrelationEngine:
    def __init__(self, rules: Optional[list[CorrelationRule]] = None):
        self.rules = rules or BUILTIN_RULES

    def correlate(self, findings: list[DetectionFinding]) -> list[CorrelationEvent]:
        events: list[CorrelationEvent] = []
        for rule in self.rules:
            event = rule.evaluate(findings)
            if event:
                events.append(event)
        return events

    def correlate_scan(self, result: ScanResult) -> ScanResult:
        events = self.correlate(result.findings)
        result.correlations = [e.to_dict() for e in events]
        if events:
            max_corr_score = max(e.score for e in events)
            result.risk_score = max(result.risk_score, max_corr_score)
        return result
