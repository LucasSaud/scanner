from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.parsers import parse_yaml_file, parse_jsonc_file, HAS_YAML
from security_scanner.config import config
from security_scanner.utils.text_utils import find_suspicious_terms_in_text


class ContainerEscapeDetector:
    def __init__(self):
        self._finding_index = 0

    def _next_id(self) -> str:
        self._finding_index += 1
        return generate_finding_id("container_escape", self._finding_index)

    def detect_docker_sock_mount(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 79: docker.sock mounts"""
        findings = []
        if "docker.sock" in content or "/var/run/docker" in content:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="CRITICAL", score=95.0,
                file_path=file_path, evidence=content[:300],
                category="container_escape",
                description="Montagem de docker.sock detectada - permite controle total do host Docker.",
                recommendation="Nunca monte /var/run/docker.sock em containers. Permite escape completo.",
                detected_terms=["docker.sock mount"],
            ))
        return findings

    def detect_host_network(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 80: host network abuse"""
        findings = []
        if "network_mode: host" in content or "network_mode: \"host\"" in content:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=80.0,
                file_path=file_path, evidence=content[:200],
                category="container_escape",
                description="Container configurado com network_mode: host - acesso total a rede do host.",
                recommendation="Evite network_mode: host. Use port mapping ou redes isoladas.",
                detected_terms=["host network"],
            ))
        return findings

    def detect_privileged_container(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect privileged mode"""
        findings = []
        if "privileged: true" in content or "privileged: \"true\"" in content:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="CRITICAL", score=92.0,
                file_path=file_path, evidence=content[:200],
                category="container_escape",
                description="Container em modo privilegiado - acesso completo ao host.",
                recommendation="Nunca execute containers em modo privileged sem necessidade extrema.",
                detected_terms=["privileged container"],
            ))
        return findings

    def detect_sensitive_volumes(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect sensitive volume mounts"""
        findings = []
        sensitive = config.suspicious_docker_volume_paths
        for path in sensitive:
            if f":{path}" in content or f" {path}:" in content:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=f"volume mount: {path}",
                    category="container_escape",
                    description=f"Container monta volume sensivel: {path} - possivel acesso a dados do host.",
                    recommendation=f"Remova a montagem de {path}. containers nao devem acessar dados sensiveis do host.",
                    detected_terms=["sensitive volume"],
                ))
        return findings

    def detect_docker_pipe_shell(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector: Dockerfile curl pipe bash"""
        findings = []
        if re.search(r"(curl|wget|fetch)\s+[^\n]*\s*\|\s*(bash|sh|zsh|fish)", content, re.IGNORECASE):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="CRITICAL", score=97.0,
                file_path=file_path, evidence=content[:300],
                category="container_escape",
                description="Dockerfile/RUN contem pipe de download para shell - supply chain attack.",
                recommendation="Nunca execute scripts baixados nao verificados em Dockerfiles.",
                detected_terms=["docker pipe shell"],
            ))
        return findings

    def detect_docker_cryptominer(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 77: Docker cryptominers"""
        findings = []
        miner_indicators = ["stratum+tcp://", "minexmr", "minergate", "cryptonight", "nanopool", "xmrpool"]
        lower = content.lower()
        for ind in miner_indicators:
            if ind in lower:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=85.0,
                    file_path=file_path, evidence=content[:300],
                    category="container_escape",
                    description=f"Indicador de cryptominer detectado: {ind}",
                    recommendation="Remova software de mineracao de criptomoedas do container.",
                    detected_terms=["cryptominer"],
                ))
                break
        return findings

    def detect_docker_ca_poison(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 78: Docker CA poisoning"""
        findings = []
        if "COPY" in content and ("ca.crt" in content or "ca.pem" in content or "ca-certificates" in content):
            if ":" not in content or "/etc/ssl/" in content or "/usr/local/share/ca-certificates" in content:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=content[:300],
                    category="container_escape",
                    description="Dockerfile faz COPY de certificado CA - possivel envenenamento de CA.",
                    recommendation="Verifique a origem do certificado CA. CA malicioso permite MITM.",
                    detected_terms=["CA poisoning"],
                ))
        return findings

    def detect_k8s_hostpath(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 83: Kubernetes hostPath abuse"""
        findings = []
        if "hostPath" in content:
            path_match = re.search(r"path:\s*(/\w+)", content)
            if path_match:
                path = path_match.group(1)
                if path in ("/", "/var/run/docker.sock", "/proc", "/dev", "/etc", "/root"):
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=85.0,
                        file_path=file_path, evidence=f"hostPath: {path}",
                        category="container_escape",
                        description=f"Kubernetes hostPath aponta para diretorio sensivel: {path}",
                        recommendation="Evite hostPath para diretorios sensiveis do node.",
                        detected_terms=["k8s hostPath"],
                    ))
        return findings

    def detect_vagrant_rce(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 84: Vagrantfile Ruby RCE"""
        findings = []
        if file_path.name == "Vagrantfile":
            lower = content.lower()
            terms = ["exec(", "`", "%x(", "system(", "inline:"]
            detected = [t for t in terms if t in lower]
            if find_suspicious_terms_in_text(lower):
                detected.extend(find_suspicious_terms_in_text(lower))
            if detected:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL" if any(t in lower for t in ["curl", "wget", "bash"]) else "HIGH",
                    score=90.0 if any(t in lower for t in ["curl", "wget", "bash"]) else 75.0,
                    file_path=file_path, evidence=content[:400],
                    category="container_escape",
                    description="Vagrantfile contem execucao de comandos Ruby - executa durante vagrant up.",
                    recommendation="Audite o Vagrantfile - executa comandos no host durante provisionamento.",
                    detected_terms=detected,
                ))
        return findings

    def detect_makefile_hidden(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 85: Makefile hidden targets"""
        findings = []
        if file_path.name.lower() in ("makefile", "gnumakefile"):
            hidden_targets = re.findall(r'^\.(\w+)\s*:', content, re.MULTILINE)
            if hidden_targets:
                for target in hidden_targets:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="MEDIUM", score=40.0,
                        file_path=file_path, evidence=f"target: .{target}",
                        category="container_escape",
                        description=f"Makefile contem target oculto '.{target}' - possivel execucao implicita.",
                        recommendation="Audite targets ocultos no Makefile.",
                        detected_terms=["hidden target"],
                    ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        if file_path.name.startswith("Dockerfile"):
            findings.extend(self.detect_docker_sock_mount(file_path, content))
            findings.extend(self.detect_docker_pipe_shell(file_path, content))
            findings.extend(self.detect_docker_cryptominer(file_path, content))
            findings.extend(self.detect_docker_ca_poison(file_path, content))

        if HAS_YAML and file_path.suffix in (".yml", ".yaml"):
            findings.extend(self.detect_host_network(file_path, content))
            findings.extend(self.detect_privileged_container(file_path, content))
            findings.extend(self.detect_sensitive_volumes(file_path, content))
            findings.extend(self.detect_docker_sock_mount(file_path, content))
            findings.extend(self.detect_k8s_hostpath(file_path, content))

        if file_path.name == "Vagrantfile":
            findings.extend(self.detect_vagrant_rce(file_path, content))

        if file_path.name.lower() in ("makefile", "gnumakefile"):
            findings.extend(self.detect_makefile_hidden(file_path, content))

        return findings
