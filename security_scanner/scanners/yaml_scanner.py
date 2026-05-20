from __future__ import annotations

from pathlib import Path

from security_scanner.detectors.ci_cd_abuse import CICDAbuseDetector
from security_scanner.models import DetectionFinding
from security_scanner.scanners.base import BaseScanner


class YAMLScanner(BaseScanner):
    name = "yaml"
    description = "Scan de YAML para abuso de CI/CD (GitHub Actions, GitLab CI, etc)"
    supported_extensions: set[str] = {".yml", ".yaml"}

    def __init__(self):
        self.ci_cd = CICDAbuseDetector()

    def can_handle(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        return ext in self.supported_extensions

    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        try:
            return self.ci_cd.scan_file(file_path, content)
        except Exception:
            return []
