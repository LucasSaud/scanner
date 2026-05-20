from __future__ import annotations

from pathlib import Path

from security_scanner.detectors.container_escape import ContainerEscapeDetector
from security_scanner.models import DetectionFinding
from security_scanner.scanners.base import BaseScanner


class DockerScanner(BaseScanner):
    name = "docker"
    description = "Scan de Dockerfile e docker-compose para escapes de container"
    supported_extensions: set[str] = {".dockerfile", ".yml", ".yaml"}

    def __init__(self):
        self.container_escape = ContainerEscapeDetector()

    def can_handle(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if name == "dockerfile" or name.endswith(".dockerfile"):
            return True
        if name in {"docker-compose.yml", "docker-compose.yaml"}:
            return True
        return False

    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        try:
            return self.container_escape.scan_file(file_path, content)
        except Exception:
            return []
