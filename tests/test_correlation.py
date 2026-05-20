from pathlib import Path

from security_scanner.correlation import CorrelationEngine, BUILTIN_RULES
from security_scanner.models import DetectionFinding, ScanResult


def _make_finding(category: str, desc: str, sev: str = "HIGH",
                  evidence: str = "", fid: str = "f1") -> DetectionFinding:
    return DetectionFinding(
        id=fid, category=category, description=desc,
        severity=sev, score=70.0, file_path=Path("test.txt"),
        evidence=evidence,
    )


class TestCorrelationEngine:
    def test_empty_findings(self):
        engine = CorrelationEngine()
        events = engine.correlate([])
        assert len(events) == 0

    def test_single_finding_no_correlation(self):
        engine = CorrelationEngine()
        f = _make_finding("supply_chain", "typosquat dep", evidence="npm install")
        events = engine.correlate([f])
        assert len(events) == 0

    def test_ide_poisoning_chain(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("ide_poisoning", "tasks autoexec", evidence="tasks.json", fid="a"),
            _make_finding("supply_chain", "postinstall curl", evidence="postinstall http://x", fid="b"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-001"]
        assert len(corr) == 1
        assert corr[0].severity == "CRITICAL"
        assert corr[0].score >= 95.0

    def test_persistence_triad(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("persistence", "git hook", fid="a"),
            _make_finding("persistence", "cron job", fid="b"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-002"]
        assert len(corr) == 1
        assert corr[0].severity == "HIGH"

    def test_supply_chain_infection(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("supply_chain", "typosquat", fid="a"),
            _make_finding("supply_chain", "extra index url", fid="b"),
            _make_finding("supply_chain", "preinstall script", fid="c"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-003"]
        assert len(corr) == 1

    def test_container_escape_pattern(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("container_escape", "docker sock mount", fid="a"),
            _make_finding("container_escape", "privileged mode", fid="b"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-004"]
        assert len(corr) == 1

    def test_exfiltration_pipeline(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("exfiltration", "env dump", fid="a"),
            _make_finding("exfiltration", "webhook url", fid="b"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-005"]
        assert len(corr) == 1

    def test_backdoor_persistence(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("backdoor", "reverse shell", fid="a"),
            _make_finding("persistence", "ssh key mod", fid="b"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-006"]
        assert len(corr) == 1

    def test_ci_cd_abuse(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("ci_cd_abuse", "pipe to shell", fid="a"),
            _make_finding("ci_cd_abuse", "unpinned action", fid="b"),
        ]
        events = engine.correlate(findings)
        corr = [e for e in events if e.rule_id == "CORR-007"]
        assert len(corr) == 1

    def test_correlate_scan_updates_result(self):
        engine = CorrelationEngine()
        findings = [
            _make_finding("backdoor", "reverse shell", fid="a"),
            _make_finding("persistence", "cron job", fid="b"),
        ]
        result = ScanResult(target=Path("."), findings=findings)
        engine.correlate_scan(result)
        assert len(result.correlations) >= 1
        assert result.risk_score >= 90.0

    def test_builtin_rules_defined(self):
        assert len(BUILTIN_RULES) == 7

    def test_correlation_event_to_dict(self):
        from security_scanner.models import CorrelationEvent
        ev = CorrelationEvent(
            id="CORR-TEST", name="Test", severity="HIGH", score=85.0,
            description="test", rule_id="R-001", finding_ids=["a", "b"],
        )
        d = ev.to_dict()
        assert d["id"] == "CORR-TEST"
        assert d["severity"] == "HIGH"
        assert d["score"] == 85.0
