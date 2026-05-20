from __future__ import annotations

from pathlib import Path

from security_scanner.models import DetectionFinding
from security_scanner.scanners.base import BaseScanner
from security_scanner.scanners.project_scanner import ProjectScanner

GLOBAL_VSCODE_DIR = Path.home() / ".vscode"


class GlobalVSCodeScanner(BaseScanner):
    name = "global_vscode"
    description = "Scan do diretorio global ~/.vscode/ (exceto extensions/)"
    enabled = True

    def __init__(self):
        self.inner = ProjectScanner()

    def can_handle(self, file_path: Path) -> bool:
        return True

    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        return self.inner.scan(file_path, content)

    @staticmethod
    def get_global_files() -> list[Path]:
        if not GLOBAL_VSCODE_DIR.exists():
            return []
        files: list[Path] = []
        for p in GLOBAL_VSCODE_DIR.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(GLOBAL_VSCODE_DIR)
            if rel.parts and rel.parts[0] == "extensions":
                continue
            files.append(p)
        return files
