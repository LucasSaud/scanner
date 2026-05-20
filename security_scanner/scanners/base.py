from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from security_scanner.models import DetectionFinding

DEFAULT_ENCODINGS = ["utf-8", "latin-1", "cp1252"]


class BaseScanner(ABC):
    name: str = ""
    description: str = ""
    enabled: bool = True
    supported_extensions: set[str] = set()

    @abstractmethod
    def can_handle(self, file_path: Path) -> bool:
        ...

    @abstractmethod
    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        ...

    def read_file_safe(self, file_path: Path) -> str:
        for enc in DEFAULT_ENCODINGS:
            try:
                return file_path.read_text(encoding=enc)
            except (UnicodeDecodeError, UnicodeError):
                continue
        return file_path.read_text(encoding="utf-8", errors="replace")
