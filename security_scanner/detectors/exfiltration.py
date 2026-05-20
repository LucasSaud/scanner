from __future__ import annotations

import json
import re
from pathlib import Path

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import find_suspicious_terms_in_text
from security_scanner.parsers import parse_jsonc_file
from security_scanner.signatures.ioc_signatures import IOCDatabase
from security_scanner.config import config

ioc_db = IOCDatabase()


class ExfiltrationDetector:
    FINDING_INDEX = [0]

    @staticmethod
    def _next_id() -> str:
        ExfiltrationDetector.FINDING_INDEX[0] += 1
        return generate_finding_id("exfiltration", ExfiltrationDetector.FINDING_INDEX[0])

    def detect_env_dump(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect env dump patterns"""
        findings = []
        patterns = [
            (r"(?:printenv|env|set)\s*(?:>|>>|\||2>)", "Dump de variaveis de ambiente para arquivo/pipe"),
            (r"curl.*-d\s*[\"'].*\$", "Curl com POST contendo variavel - possivel exfiltracao de env"),
            (r"wget.*--post-data.*\$", "Wget com POST contendo variavel"),
            (r"process\.env\[[\"']\w+[\"']\]", "Acesso a process.env em JS - possivel exfiltracao"),
        ]
        for pat, desc in patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:300],
                    category="exfiltration",
                    description=desc,
                    recommendation="Investigue se ha exfiltracao de variaveis de ambiente.",
                    detected_terms=["env exfil"],
                ))
        return findings

    def detect_slack_webhook(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect Slack/Discord webhook exfiltration"""
        findings = []
        webhook_patterns = [
            (r"hooks\.slack\.com", "Slack webhook"),
            (r"discord(?:app)?\.com/api/webhooks", "Discord webhook"),
            (r"api\.telegram\.org", "Telegram bot API"),
        ]
        for pat, name in webhook_patterns:
            if re.search(pat, content, re.IGNORECASE):
                match = re.search(r"(https?://[^\s\"']+)", content[content.lower().find(pat.split("\\")[0]):])
                url = match.group(1)[:100] if match else pat
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=url,
                    category="exfiltration",
                    description=f"URL de {name} detectada - possivel exfiltracao de dados.",
                    recommendation="Verifique se o webhook e legitimo. Webhooks podem exfiltrar dados do ambiente.",
                    detected_terms=[f"{name} exfil"],
                ))
        return findings

    def detect_ngrok_tunnel(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect ngrok/localhost tunnel"""
        findings = []
        tunnel_patterns = ["ngrok", "localtunnel", "serveo", "localhost.run", "bore.pub"]
        for pat in tunnel_patterns:
            if pat.lower() in content.lower():
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:300],
                    category="exfiltration",
                    description=f"Tunel '{pat}' detectado - possivel exfiltracao ou C2.",
                    recommendation="Investigue o uso de tunneling. Nao use tunneis em projetos nao confiaveis.",
                    detected_terms=[f"{pat} tunnel"],
                ))
                break
        return findings

    def detect_dns_exfil(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect DNS exfiltration patterns"""
        findings = []
        patterns = [
            (r"nslookup\s+(?:`|\$\()", "nslookup com subshell - possivel exfiltracao DNS"),
            (r"dig\s+(?:`|\$\()", "dig com subshell - possivel exfiltracao DNS"),
            (r"host\s+(?:`|\$\()", "host com subshell - possivel exfiltracao DNS"),
            (r"curl.*sub", "curl para subdominio - possivel blind data exfil"),
        ]
        for pat, desc in patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:300],
                    category="exfiltration",
                    description=desc,
                    recommendation="Investigue exfiltracao via DNS. Atacantes usam DNS para exfiltrar dados.",
                    detected_terms=["dns exfil"],
                ))
        return findings

    def detect_ioc_urls(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect IOC URLs in file"""
        findings = []
        matches = ioc_db.match(content)
        for ioc in matches:
            if ioc.category in ("exfiltration", "tunnel", "cryptominer"):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity=ioc.severity, score=75.0 if ioc.severity == "HIGH" else 55.0,
                    file_path=file_path, evidence=ioc.value,
                    category="exfiltration",
                    description=f"IOC detectado: {ioc.description or ioc.value}",
                    recommendation=ioc.description or "Investigue a URL detectada.",
                    detected_terms=[ioc.value, ioc.category],
                ))
        return findings

    def detect_sensitive_env_secrets(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 96: malicious .env"""
        findings = []
        sensitive = config.env_sensitive_keys
        for i, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key = line.split("=", 1)[0].strip().upper()
            val = line.split("=", 1)[1].strip().strip('"').strip("'")
            if key in sensitive and val and not val.startswith("${"):
                findings.append(DetectionFinding(
                    id=self._next_id(),
                    severity="HIGH" if re.search(r"://[^:]+:[^@]+@", val) else "MEDIUM",
                    score=80.0 if re.search(r"://[^:]+:[^@]+@", val) else 60.0,
                    file_path=file_path, evidence=f"{key}={val[:80]}",
                    category="exfiltration", line=i,
                    description=f"Arquivo .env contem segredo: {key}",
                    recommendation=f"Remova {key} do .env e use secrets do CI/CD ou variaveis de ambiente.",
                    detected_terms=[key, "env secret"],
                ))
        return findings

    def detect_middleware_exfil(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 17: middleware env exfiltration"""
        findings = []
        if re.search(r"(?:middleware|app\.use|router\.use)", content, re.IGNORECASE):
            if re.search(r"(?:process\.env|process\.env\[\w+\])", content):
                if re.search(r"(?:res\.send|res\.json|res\.end|fetch|axios|got|request)", content):
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=content[:400],
                        category="exfiltration",
                        description="Middleware que acessa process.env e envia resposta - possivel exfiltracao de env vars.",
                        recommendation="Audite middlewares que expoem variaveis de ambiente via HTTP.",
                        detected_terms=["middleware env exfil"],
                    ))
        return findings

    def detect_curl_python_abuse(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 91: curl|python abuse"""
        findings = []
        if re.search(r"curl\s+[^\n]*\s*\|\s*python", content, re.IGNORECASE):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="CRITICAL", score=95.0,
                file_path=file_path, evidence=content[:200],
                category="exfiltration",
                description="Pipe de download direto para python - execucao remota de script.",
                recommendation="Nunca execute scripts baixados diretamente. Use verificacao de checksum.",
                detected_terms=["curl|python abuse"],
            ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        findings.extend(self.detect_env_dump(file_path, content))
        findings.extend(self.detect_slack_webhook(file_path, content))
        findings.extend(self.detect_ngrok_tunnel(file_path, content))
        findings.extend(self.detect_dns_exfil(file_path, content))
        findings.extend(self.detect_ioc_urls(file_path, content))
        findings.extend(self.detect_curl_python_abuse(file_path, content))
        findings.extend(self.detect_middleware_exfil(file_path, content))

        if file_path.name.startswith(".env"):
            findings.extend(self.detect_sensitive_env_secrets(file_path, content))

        return findings
