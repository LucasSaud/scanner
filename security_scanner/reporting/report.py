from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from security_scanner.models import ScanResult


class ReportGenerator(ABC):
    extension: str = ""

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        ...

    def save(self, result: ScanResult, output_path: Path) -> Path:
        content = self.generate(result)
        if not output_path.suffix:
            output_path = output_path.with_suffix(f".{self.extension}")
        output_path.write_text(content, encoding="utf-8")
        return output_path


class JSONReport(ReportGenerator):
    extension = "json"

    def generate(self, result: ScanResult) -> str:
        return json.dumps(result.to_dict(), indent=2, default=str)
