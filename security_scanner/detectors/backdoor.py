from __future__ import annotations

import re
from pathlib import Path

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import find_suspicious_terms_in_text
from security_scanner.signatures.shell_signatures import SHELL_DANGEROUS_PATTERNS
from security_scanner.signatures.base64_signatures import ENCODING_SIGNATURES
from security_scanner.signatures.obfuscation_signatures import OBFUSCATION_SIGNATURE_PATTERNS


class BackdoorDetector:
    def __init__(self):
        self._finding_index = 0

    def _next_id(self) -> str:
        self._finding_index += 1
        return generate_finding_id("backdoor", self._finding_index)

    def detect_reverse_shells(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vectors: reverse shell detection"""
        findings = []
        for sig_id, sig in SHELL_DANGEROUS_PATTERNS.items():
            if "reverse" in sig_id or "tcp" in sig_id:
                if re.search(sig["pattern"], content, re.IGNORECASE):
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity=sig["severity"], score=sig["score"],
                        file_path=file_path, evidence=content[:300],
                        category="backdoor",
                        description=sig["description"],
                        recommendation="Reverse shell detectado - investigue imediatamente.",
                        detected_terms=[sig_id],
                    ))
        # Additional generic reverse shell patterns
        extra_patterns = [
            (r"(?:python|perl|ruby|php)\s+-[ce]\s+['\"].*socket.*connect", "Reverse shell via interpretador"),
            (r"mknod\s+\/tmp\/backpipe\s+p", "Named pipe backdoor (mknod)"),
            (r"(?:ncat|nc\.exe)\s+-e\s+(?:cmd\.exe|/bin/bash|/bin/sh)", "Netcat bind shell"),
            (r"powershell.*New-Object.*Net\.Sockets\.TcpClient", "PowerShell reverse shell"),
            (r"(?:bash|sh|zsh)\s+-i\s+>&?\s*/dev/(?:tcp|udp)/", "Reverse shell via /dev/tcp"),
        ]
        for pat, desc in extra_patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL", score=98.0,
                    file_path=file_path, evidence=content[:300],
                    category="backdoor", description=desc,
                    recommendation="Reverse shell detectado - risco de comprometimento total.",
                    detected_terms=["reverse shell"],
                ))
        return findings

    def detect_bind_shells(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect bind shells"""
        findings = []
        patterns = [
            (r"nc\s+(?:-lvp|-l|-lp)\s+\d+", "Netcat bind shell listening on port"),
            (r"socat\s+(?:TCP-LISTEN|tcp-l)", "Socat bind listener"),
            (r"python.*SimpleHTTPServer|python.*HTTPServer", "SimpleHTTPServer - possivel backdoor"),
            (r"while\s+true;.*nc.*-l.*;.*done", "Loop de bind shell"),
            (r"listen\s*\(\s*\d{4,5}\s*\)", "Socket listening on high port"),
        ]
        for pat, desc in patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL", score=95.0,
                    file_path=file_path, evidence=content[:300],
                    category="backdoor", description=desc,
                    recommendation="Bind shell detectado - pode permitir acesso remoto.",
                    detected_terms=["bind shell"],
                ))
        return findings

    def detect_hidden_backdoors(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect hidden backdoor patterns"""
        findings = []
        patterns = [
            (r"\.id_rsa|\.authorized_keys", "Possivel backdoor via SSH key"),
            (r"chmod\s+0600.*authorized_keys", "Adicao de chave SSH em authorized_keys"),
            (r"echo\s+.*ssh-rsa.*>>.*authorized_keys", "Injecao de chave SSH"),
            (r"useradd.*-o.*-u.*0.*-g.*0", "Criacao de usuario com UID 0 (root)"),
            (r"usermod.*-u.*0", "Alteracao de UID para 0"),
            (r"backdoor|backd00r|back_door|bd\.\w+", "Referencia a backdoor"),
        ]
        for pat, desc in patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL" if "ssh" in pat or "authorized" in pat else "HIGH",
                    score=90.0 if "ssh" in pat else 75.0,
                    file_path=file_path, evidence=content[:300],
                    category="backdoor", description=desc,
                    recommendation="Investigue sinais de backdoor no sistema.",
                    detected_terms=["backdoor"],
                ))
        return findings

    def detect_abnormal_ports(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect abnormal port usage"""
        findings = []
        suspicious_ports = ["4444", "5555", "6666", "6667", "7777", "8888", "9999", "1337", "31337", "4443"]
        for port in suspicious_ports:
            if re.search(rf":{port}\b", content) and re.search(r"(?:connect|bind|listen)", content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:200],
                    category="backdoor",
                    description=f"Uso de porta suspeita {port} em operacao de rede - possivel backdoor ou C2.",
                    recommendation="Investigate o uso de portas nao padrao para comunicacao.",
                    detected_terms=[f"port {port}"],
                ))
        return findings

    def detect_nginx_backdoor(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 100: nginx routing backdoors"""
        findings = []
        if file_path.name == "nginx.conf" or file_path.suffix == ".conf":
            lower = content.lower()
            if "proxy_pass" in lower:
                match = re.search(r"proxy_pass\s+(https?://[^;]+)", content, re.IGNORECASE)
                if match:
                    url = match.group(1)
                    if not any(d in url for d in ["localhost", "127.0.0.1", "unix:"]):
                        findings.append(DetectionFinding(
                            id=self._next_id(), severity="HIGH", score=70.0,
                            file_path=file_path, evidence=url,
                            category="backdoor",
                            description=f"nginx proxy_pass aponta para URL externa: {url[:80]} - possivel backdoor de roteamento.",
                            recommendation="Verifique se o proxy_pass e legitimo. Roteamento malicioso pode redirecionar trafego.",
                            detected_terms=["nginx backdoor"],
                        ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        findings.extend(self.detect_reverse_shells(file_path, content))
        findings.extend(self.detect_bind_shells(file_path, content))
        findings.extend(self.detect_hidden_backdoors(file_path, content))
        findings.extend(self.detect_abnormal_ports(file_path, content))
        findings.extend(self.detect_nginx_backdoor(file_path, content))
        return findings
