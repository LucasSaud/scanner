import json
import time
from pathlib import Path

from security_scanner.telemetry import ScanMetrics, ScanStarted, FileScanned
from security_scanner.telemetry import FindingDetected, ScanCompleted, CorrelationMatch
from security_scanner.telemetry import telemetry_logger


class TestScanEvents:
    def test_scan_started(self):
        e = ScanStarted(path=Path("/test"), scan_id="abc123")
        assert e.event_type == "scan_started"
        assert e.data["path"] == "/test"
        assert e.data["scan_id"] == "abc123"

    def test_file_scanned(self):
        e = FileScanned(file_path=Path("test.py"), scanner_name="project",
                        duration_ms=50, finding_count=2)
        assert e.event_type == "file_scanned"
        assert e.data["scanner"] == "project"

    def test_finding_detected(self):
        e = FindingDetected(finding_id="f1", severity="HIGH",
                            category="supply_chain", file_path=Path("pkg.json"))
        assert e.event_type == "finding_detected"
        assert e.data["severity"] == "HIGH"

    def test_scan_completed(self):
        e = ScanCompleted(scan_id="s1", duration_ms=1000,
                          total_files=50, total_findings=3, risk_score=85.0)
        assert e.event_type == "scan_completed"
        assert e.data["risk_score"] == 85.0

    def test_correlation_match(self):
        e = CorrelationMatch(rule_id="CORR-001", name="Chain",
                             severity="CRITICAL", score=95.0,
                             finding_ids=["a", "b"])
        assert e.event_type == "correlation_match"
        assert e.data["rule_id"] == "CORR-001"

    def test_timestamp_auto(self):
        e = ScanStarted(path=Path("/test"), scan_id="x")
        assert e.timestamp

    def test_to_dict(self):
        e = ScanStarted(path=Path("/p"), scan_id="s1")
        d = e.to_dict()
        assert d["event_type"] == "scan_started"
        assert d["data"]["path"] == "/p"


class TestScanMetrics:
    def setup_method(self):
        self.m = ScanMetrics(start_time=time.time())

    def test_initial_state(self):
        assert self.m.total_scans == 0
        assert self.m.total_files == 0

    def test_record_scan(self):
        self.m.record_scan(files=10, findings=2, correlations=1, duration_ms=500)
        assert self.m.total_scans == 1
        assert self.m.total_files == 10
        assert self.m.total_findings == 2
        assert self.m.total_correlations == 1

    def test_record_finding(self):
        self.m.record_finding("HIGH", "supply_chain")
        assert self.m.findings_by_severity["HIGH"] == 1
        assert self.m.findings_by_category["supply_chain"] == 1

    def test_avg_duration(self):
        self.m.record_scan(1, 0, 0, 100)
        self.m.record_scan(1, 0, 0, 300)
        assert self.m.avg_duration_ms == 200.0

    def test_avg_duration_zero(self):
        assert self.m.avg_duration_ms == 0.0

    def test_reset(self):
        self.m.record_scan(1, 1, 0, 100)
        self.m.reset()
        assert self.m.total_scans == 0
        assert self.m.total_files == 0

    def test_to_dict(self):
        self.m.record_scan(5, 1, 0, 200)
        d = self.m.to_dict()
        assert d["total_scans"] == 1
        assert d["total_files"] == 5
        assert "avg_duration_ms" in d
        assert "uptime_seconds" in d

    def test_uptime(self):
        assert self.m.uptime_seconds >= 0


class TestTelemetryLogger:
    def test_logger_created(self):
        assert telemetry_logger is not None

    def test_info(self):
        telemetry_logger.info("test_event", detail="hello")
        assert True

    def test_warning(self):
        telemetry_logger.warning("test_warning", code=42)
        assert True

    def test_error(self):
        telemetry_logger.error("test_error", exc="something")
        assert True

    def test_logger_disabled(self):
        from security_scanner.telemetry.logger import TelemetryLogger
        logger = TelemetryLogger(enabled=False)
        logger.info("should_not_crash")
        assert True
