from __future__ import annotations

from pathlib import Path

from security_scanner.detectors import (
    SupplyChainDetector,
    IDEPoisoningDetector,
    PersistenceDetector,
    ExfiltrationDetector,
    CommandInjectionDetector,
    BackdoorDetector,
    ContainerEscapeDetector,
    CICDAbuseDetector,
)
from security_scanner.models import DetectionFinding
from security_scanner.scanners.base import BaseScanner


class ProjectScanner(BaseScanner):
    name = "project"
    description = "Scanner principal — analisa arquivos com todos os detectores"
    supported_extensions: set[str] = {
        ".json", ".jsonc", ".js", ".ts", ".py", ".sh", ".bash", ".zsh",
        ".yml", ".yaml", ".toml", ".cfg", ".conf", ".ini", ".env",
        ".ps1", ".bat", ".cmd", ".rb", ".pl", ".php", ".go", ".rs",
        ".dockerfile", "dockerfile", ".tf",
    }

    def __init__(self):
        self.supply_chain = SupplyChainDetector()
        self.ide_poisoning = IDEPoisoningDetector()
        self.persistence = PersistenceDetector()
        self.exfiltration = ExfiltrationDetector()
        self.command_injection = CommandInjectionDetector()
        self.backdoor = BackdoorDetector()
        self.container_escape = ContainerEscapeDetector()
        self.ci_cd_abuse = CICDAbuseDetector()

    def can_handle(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        name = file_path.name.lower()
        if ext in self.supported_extensions:
            return True
        if name in {"dockerfile", "makefile", "gemfile", "vagrantfile"}:
            return True
        if name.endswith(".gitignore") or name.endswith(".gitattributes"):
            return True
        return False

    def scan(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        detectors = [
            self.supply_chain,
            self.ide_poisoning,
            self.persistence,
            self.exfiltration,
            self.command_injection,
            self.backdoor,
            self.container_escape,
            self.ci_cd_abuse,
        ]
        for det in detectors:
            try:
                det_findings = det.scan_file(file_path, content)
                if det_findings:
                    findings.extend(det_findings)
            except Exception:
                continue
        return findings
