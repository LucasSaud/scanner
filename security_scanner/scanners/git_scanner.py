from __future__ import annotations

from pathlib import Path

from security_scanner.detectors.persistence import PersistenceDetector
from security_scanner.models import DetectionFinding
from security_scanner.scanners.base import BaseScanner


class GitScanner(BaseScanner):
    name = "git"
    description = "Scan de arquivos .git/ (hooks, config, modules)"
    supported_extensions: set[str] = {"", ".sample", ".sh", ".bash"}

    def __init__(self):
        self.persistence = PersistenceDetector()

    def can_handle(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        parent = file_path.parent.name.lower() if file_path.parent else ""
        if ".git" in file_path.parts:
            return True
        if name == ".gitmodules" or name == ".gitattributes" or name == ".gitignore":
            return True
        if parent == "hooks":
            return True
        return False

    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        name = file_path.name.lower()
        if name == ".gitmodules" or name.endswith(".gitignore") or name.endswith(".gitattributes"):
            return findings
        try:
            findings.extend(self.persistence.scan_file(file_path, content))
        except Exception:
            pass
        return findings
