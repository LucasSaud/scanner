from __future__ import annotations

from pathlib import Path

from security_scanner.detectors.exfiltration import ExfiltrationDetector
from security_scanner.models import DetectionFinding
from security_scanner.scanners.base import BaseScanner


class EnvScanner(BaseScanner):
    name = "env"
    description = "Scan de arquivos .env para secrets e exfiltracao"
    supported_extensions: set[str] = {".env"}

    def __init__(self):
        self.exfiltration = ExfiltrationDetector()

    def can_handle(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name == ".env" or name.startswith(".env.") or name == "environment.yml"

    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        try:
            return self.exfiltration.scan_file(file_path, content)
        except Exception:
            return []
