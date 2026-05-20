from pathlib import Path

from security_scanner.rules import RulesLoader, RuleOverride


class TestRuleOverride:
    def test_defaults(self):
        o = RuleOverride(category="test", pattern="curl", label="curl detect")
        assert o.category == "test"
        assert o.pattern == "curl"
        assert o.label == "curl detect"
        assert o.score == 0.0
        assert o.enabled is True


class TestRulesLoader:
    def setup_method(self):
        self.loader = RulesLoader()

    def test_load_rules_exists(self):
        assert self.loader._rules is not None
        assert len(self.loader._rules) > 0

    def test_all_categories(self):
        cats = self.loader.all_categories
        assert isinstance(cats, list)

    def test_get_overrides_unknown_returns_empty(self):
        overrides = self.loader.get_overrides("nonexistent")
        assert overrides == []

    def test_reload_does_not_crash(self):
        self.loader.reload()
        assert True

    def test_rule_override_patterns(self):
        o = RuleOverride(category="supply_chain", pattern="evil.*",
                         label="evil pattern", score=9.5)
        assert o.pattern == "evil.*"
        assert o.score == 9.5
        assert o.enabled is True
        d = o.metadata
        assert d == {}
