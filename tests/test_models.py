from pathlib import Path

from security_scanner.models import DetectionFinding, ScanResult, SeverityCounts
from security_scanner.models.finding import severity_from_score, generate_finding_id


def test_finding_defaults():
    f = DetectionFinding(severity="HIGH", file_path=Path("/test/file"), description="Test finding", evidence="test")
    assert f.id != ""
    assert f.title == "Test finding"
    assert f.score == 50.0
    assert f.line is None


def test_finding_backward_compat():
    f = DetectionFinding(
        severity="HIGH", file_path=Path("/test/file"), description="Test",
        evidence="test", line_number=10, risk_score=8.0, suggestion="Fix it",
    )
    assert f.line == 10
    assert f.score == 80.0
    assert f.recommendation == "Fix it"


def test_finding_to_dict():
    f = DetectionFinding(severity="CRITICAL", file_path=Path("/test/file"), description="Critical issue", evidence="evil")
    d = f.to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["score"] == 50.0


def test_severity_from_score():
    assert severity_from_score(10) == "INFO"
    assert severity_from_score(30) == "LOW"
    assert severity_from_score(50) == "MEDIUM"
    assert severity_from_score(70) == "HIGH"
    assert severity_from_score(95) == "CRITICAL"


def test_generate_finding_id():
    assert generate_finding_id("supply_chain", 1).startswith("SC-")
    assert generate_finding_id("ide_poisoning", 42).startswith("ID-")
    assert generate_finding_id("unknown", 5).startswith("GN-")


def test_severity_counts():
    findings = [
        DetectionFinding(severity="CRITICAL", file_path=Path("/a"), description="a", evidence="a"),
        DetectionFinding(severity="HIGH", file_path=Path("/b"), description="b", evidence="b"),
        DetectionFinding(severity="MEDIUM", file_path=Path("/c"), description="c", evidence="c"),
    ]
    counts = SeverityCounts.from_findings(findings)
    assert counts.critical == 1
    assert counts.high == 1
    assert counts.medium == 1
    assert counts.low == 0


def test_scan_result():
    findings = [
        DetectionFinding(severity="HIGH", file_path=Path("/a"), description="a", evidence="a", score=75.0),
    ]
    result = ScanResult(target=Path("/project"), findings=findings)
    assert result.total_findings == 1
    assert result.risk_score == 75.0
    assert result.severity_counts.high == 1
