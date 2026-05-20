from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib


_RULES_PATH = Path(__file__).resolve().parent.parent / "rules.toml"


def _load_rules() -> dict:
    try:
        with open(_RULES_PATH, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


_RULES: dict = _load_rules()


class ScannerConfig:
    def __init__(self, rules: Optional[dict] = None):
        self._rules = rules or _RULES

    @classmethod
    def reload(cls) -> ScannerConfig:
        return cls(_load_rules())

    @property
    def suspicious_execution_terms(self) -> list[str]:
        return self._rules.get("suspicious", {}).get("execution_terms", [])

    @property
    def url_patterns(self) -> list[str]:
        return self._rules.get("suspicious", {}).get("url_patterns", [])

    @property
    def suspicious_file_extensions(self) -> set[str]:
        return set(self._rules.get("suspicious", {}).get("file_extensions_in_vscode_root", []))

    @property
    def npm_auto_hooks(self) -> list[str]:
        return self._rules.get("npm", {}).get("auto_execution_hooks", [])

    @property
    def devcontainer_auto_keys(self) -> list[str]:
        return self._rules.get("devcontainer", {}).get("auto_execution_keys", [])

    @property
    def dangerous_vscode_settings(self) -> list[str]:
        return self._rules.get("vscode", {}).get("dangerous_settings_keys", [])

    @property
    def entropy_threshold(self) -> float:
        return self._rules.get("detection", {}).get("entropy_threshold", 4.5)

    @property
    def excluded_directory_names(self) -> set[str]:
        return set(self._rules.get("scan", {}).get("excluded_dirs", [
            ".venv", "venv", "env", "node_modules", "site-packages",
            "__pycache__", ".tox", ".eggs", "dist", "build",
            ".mypy_cache", ".pytest_cache", ".git",
        ]))

    @property
    def max_file_size_bytes(self) -> int:
        return self._rules.get("scan", {}).get("max_file_size_bytes", 5 * 1024 * 1024)

    @property
    def parallel_workers(self) -> int:
        return self._rules.get("scan", {}).get("parallel_workers", 4)

    @property
    def ioc_domains(self) -> list[str]:
        return self._rules.get("ioc", {}).get("domains", [])

    @property
    def ioc_ips(self) -> list[str]:
        return self._rules.get("ioc", {}).get("ips", [])

    @property
    def ioc_tlds(self) -> list[str]:
        return self._rules.get("ioc", {}).get("suspicious_tlds", [])

    @property
    def suspicious_docker_volume_paths(self) -> set[str]:
        return set(self._rules.get("docker", {}).get("suspicious_volume_paths", [
            "/root/.ssh", "/root/.aws", "/root/.config",
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "/var/run/docker.sock", "/", "/bin", "/usr/bin",
        ]))

    @property
    def suspicious_docker_cap_add(self) -> set[str]:
        return set(self._rules.get("docker", {}).get("suspicious_cap_add", [
            "ALL", "SYS_ADMIN", "SYS_MODULE",
            "SYS_RAWIO", "SYS_PTRACE", "NET_ADMIN",
            "SYS_BOOT", "SYSLOG",
        ]))

    @property
    def env_sensitive_keys(self) -> list[str]:
        return self._rules.get("env", {}).get("sensitive_keys", [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
            "GCP_SERVICE_KEY", "GOOGLE_API_KEY",
            "DB_PASSWORD", "DATABASE_URL",
            "API_KEY", "API_SECRET", "SECRET_KEY",
            "TOKEN", "PASSWORD", "PASSWD",
            "PRIVATE_KEY", "SSH_KEY",
            "STRIPE_SECRET", "STRIPE_KEY",
            "JWT_SECRET", "JWT_TOKEN",
            "SLACK_TOKEN", "SLACK_WEBHOOK",
        ])

    @property
    def bundler_high_signal_patterns(self) -> list[tuple[str, str, float]]:
        raw = self._rules.get("bundler", {}).get("high_signal_patterns", [])
        if raw:
            return [(p["pattern"], p["label"], p["score"]) for p in raw]
        return DEFAULT_BUNDLER_PATTERNS

    @property
    def misc_dangerous_env_keys(self) -> set[str]:
        return set(self._rules.get("misc", {}).get("dangerous_env_keys", [
            "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
            "PATH", "PYTHONPATH", "NODE_PATH",
            "LD_LIBRARY_PATH", "RUBYLIB",
        ]))

    @property
    def homoglyph_map(self) -> dict[str, str]:
        return dict(self._rules.get("detection", {}).get("homoglyphs", {}))

    def get(self, *keys: str, default: Any = None) -> Any:
        val = self._rules
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k, {})
            else:
                return default
        return val if val != {} else default


DEFAULT_BUNDLER_PATTERNS: list[tuple[str, str, float]] = [
    (r"child_process", "child_process import/referencia", 8.5),
    (r"exec\s*\(.*curl|exec\s*\(.*wget|exec\s*\(.*base64", "exec com download/base64", 9.5),
    (r"exec\s*\(", "chamada exec()", 8.0),
    (r"spawn\s*\(", "chamada spawn()", 8.0),
    (r"fromCharCode|join\s*\(\s*['\"]['\"]\s*\)", "ofuscacao JS em config", 9.0),
    (r"writeFileSync\s*\(|writeFile\s*\(", "escrita de arquivo síncrona", 8.5),
    (r"process\.env\[|net\.connect\s*\(|dns\.resolve\s*\(|dns\.lookup\s*\(", "exfiltracao/env/dns", 8.5),
    (r"base64.*decode|Buffer\.from\s*\(.*base64", "base64 decode em config", 8.5),
    (r"require\s*\(['\"]child_process['\"]", "require child_process", 8.5),
]


config = ScannerConfig()
