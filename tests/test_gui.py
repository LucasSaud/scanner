import pytest

pytest.importorskip("customtkinter")

from pathlib import Path


class TestDashboard:
    def test_stats_frame_update(self):
        import customtkinter as ctk
        from gui.dashboard import StatsFrame
        root = ctk.CTk()
        try:
            sf = StatsFrame(root)
            sf.update(total=5, critical=2, high=1, files=100)
            assert sf._total_label.cget("text") == "5"
            assert sf._critical_label.cget("text") == "2"
            assert sf._high_label.cget("text") == "1"
            assert sf._file_count_label.cget("text") == "100"
        finally:
            root.destroy()

    def test_risk_meter_low(self):
        import customtkinter as ctk
        from gui.dashboard import RiskMeter
        root = ctk.CTk()
        try:
            rm = RiskMeter(root)
            rm.set_risk(20.0)
            assert "20" in rm._label.cget("text")
        finally:
            root.destroy()

    def test_risk_meter_critical(self):
        import customtkinter as ctk
        from gui.dashboard import RiskMeter
        root = ctk.CTk()
        try:
            rm = RiskMeter(root)
            rm.set_risk(95.0)
            assert "95" in rm._label.cget("text")
        finally:
            root.destroy()


class TestCorrelationCard:
    def test_card_created(self):
        import customtkinter as ctk
        from gui.correlation_view import CorrelationCard
        root = ctk.CTk()
        try:
            event = {
                "id": "CORR-test", "name": "Test Chain",
                "severity": "CRITICAL", "score": 95.0,
                "description": "Test desc", "rule_id": "CORR-001",
                "finding_ids": ["a", "b"], "recommendation": "Fix this",
            }
            card = CorrelationCard(root, event)
            assert card is not None
        finally:
            root.destroy()
