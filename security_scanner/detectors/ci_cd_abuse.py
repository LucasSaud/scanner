from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import find_suspicious_terms_in_text
from security_scanner.parsers import parse_yaml_file, HAS_YAML


class CICDAbuseDetector:
    def __init__(self):
        self._finding_index = 0

    def _next_id(self) -> str:
        self._finding_index += 1
        return generate_finding_id("ci_cd_abuse", self._finding_index)

    def detect_actions_pipe_shell(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 71: curl pipe bash em Actions"""
        findings = []
        if re.search(r"(curl|wget|fetch)\s+[^\n]*\s*\|\s*(bash|sh|zsh|fish)", content, re.IGNORECASE):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="CRITICAL", score=97.0,
                file_path=file_path, evidence=content[:400],
                category="ci_cd_abuse",
                description="GitHub Actions workflow contem pipe de download para shell - supply chain attack.",
                recommendation="Substitua por acoes oficiais. Nunca execute scripts baixados em CI/CD.",
                detected_terms=["pipe shell in CI"],
            ))
        return findings

    def detect_unpinned_actions(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 72: unpinned GitHub actions"""
        findings = []
        for match in re.finditer(r"uses:\s*['\"]?(\S+)['\"]?", content):
            uses = match.group(1)
            if "@" in uses:
                ref = uses.split("@")[1]
                if not re.match(r"^[a-f0-9]{40}$", ref) and not ref.startswith("refs/"):
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=uses,
                        category="ci_cd_abuse",
                        description=f"GitHub Action usa ref mutavel: {uses} - possivel supply chain.",
                        recommendation="Fixe a versao da action com SHA completo do commit.",
                        detected_terms=["unpinned action"],
                    ))
        return findings

    def detect_gitlab_exfil(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 73: GitLab artifact exfil"""
        findings = []
        lower = content.lower()
        if "artifacts" in lower:
            if "curl" in lower or "wget" in lower or "http://" in lower:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="ci_cd_abuse",
                    description="GitLab CI com artefatos e comandos de rede - possivel exfiltracao.",
                    recommendation="Audite jobs do GitLab CI que acessam rede e exportam artefatos.",
                    detected_terms=["gitlab exfil"],
                ))
        return findings

    def detect_bitbucket_pipeline(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 74: Bitbucket malicious pipelines"""
        findings = []
        if "bitbucket-pipelines.yml" in str(file_path):
            lower = content.lower()
            terms = find_suspicious_terms_in_text(lower)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="ci_cd_abuse",
                    description="Bitbucket pipeline contem comandos suspeitos.",
                    recommendation="Audite pipelines do Bitbucket.",
                    detected_terms=terms,
                ))
        return findings

    def detect_circleci_shell(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 75: CircleCI reverse shell"""
        findings = []
        if ".circleci/" in str(file_path) or "circleci" in str(file_path).lower():
            lower = content.lower()
            if "reverse" in lower or "/dev/tcp/" in lower or "bash -i" in lower:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL", score=95.0,
                    file_path=file_path, evidence=content[:400],
                    category="ci_cd_abuse",
                    description="CircleCI config contem indicadores de reverse shell.",
                    recommendation="Investigue imediatamente - possivel compromise do CI.",
                    detected_terms=["reverse shell in CI"],
                ))
        return findings

    def detect_jenkins_base64(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 76: Jenkins base64 payloads"""
        findings = []
        if file_path.name == "Jenkinsfile" or "jenkins" in str(file_path).lower():
            lower = content.lower()
            if "base64" in lower and any(t in lower for t in ["decode", "-d", "--decode"]):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=content[:400],
                    category="ci_cd_abuse",
                    description="Jenkinsfile contem decode base64 - possivel payload ofuscado.",
                    recommendation="Audite pipelines Jenkins que usam base64 decode.",
                    detected_terms=["jenkins base64"],
                ))
        return findings

    def detect_terraform_exec(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 81: Terraform local-exec"""
        findings = []
        if file_path.suffix == ".tf" or file_path.name == "terraform.tf":
            if "local-exec" in content or "local_exec" in content:
                terms = find_suspicious_terms_in_text(content.lower())
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=80.0,
                        file_path=file_path, evidence=content[:400],
                        category="ci_cd_abuse",
                        description="Terraform local-exec contem comandos perigosos - executa no host durante apply.",
                        recommendation="Evite local-exec com comandos nao confiaveis. Use provisioners remotos.",
                        detected_terms=terms,
                    ))
        return findings

    def detect_ansible_obfus(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 82: Ansible obfuscation"""
        findings = []
        if file_path.suffix in (".yml", ".yaml") and "ansible" in str(file_path).lower() or "playbook" in str(file_path).lower():
            lower = content.lower()
            if "shell:" in lower or "command:" in lower:
                terms = find_suspicious_terms_in_text(lower)
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=70.0,
                        file_path=file_path, evidence=content[:400],
                        category="ci_cd_abuse",
                        description="Playbook Ansible contem comandos shell/command com termos suspeitos.",
                        recommendation="Audite tasks shell/command no playbook Ansible.",
                        detected_terms=terms,
                    ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        str_path = str(file_path)
        name = file_path.name

        # GitHub Actions
        if ".github/workflows/" in str_path and file_path.suffix in (".yml", ".yaml"):
            findings.extend(self.detect_actions_pipe_shell(file_path, content))
            findings.extend(self.detect_unpinned_actions(file_path, content))
            if HAS_YAML:
                data = parse_yaml_file(file_path)
                if data:
                    for job_name, job in data.get("jobs", {}).items():
                        if isinstance(job, dict) and job.get("uses"):
                            uses = str(job["uses"])
                            if "/" in uses and "@" in uses:
                                ref = uses.split("@")[1]
                                if not re.match(r"^[a-f0-9]{40}$", ref) and not ref.startswith("refs/"):
                                    findings.append(DetectionFinding(
                                        id=self._next_id(), severity="HIGH", score=75.0,
                                        file_path=file_path, evidence=uses,
                                        category="ci_cd_abuse",
                                        description=f"Workflow_call '{job_name}' usa action com ref mutavel: {uses}",
                                        recommendation="Fixe com SHA completo.",
                                        detected_terms=["workflow_call unpinned"],
                                    ))

        # GitLab CI
        if name == ".gitlab-ci.yml":
            findings.extend(self.detect_gitlab_exfil(file_path, content))

        # Bitbucket
        if name == "bitbucket-pipelines.yml":
            findings.extend(self.detect_bitbucket_pipeline(file_path, content))

        # CircleCI
        if ".circleci/" in str_path and file_path.suffix in (".yml", ".yaml"):
            findings.extend(self.detect_circleci_shell(file_path, content))

        # Jenkins
        if name == "Jenkinsfile":
            findings.extend(self.detect_jenkins_base64(file_path, content))

        # Terraform
        if file_path.suffix == ".tf":
            findings.extend(self.detect_terraform_exec(file_path, content))

        # Ansible
        if name.endswith((".yml", ".yaml")) and ("ansible" in str_path.lower() or "playbook" in str_path.lower() or "tasks" in str_path.lower()):
            findings.extend(self.detect_ansible_obfus(file_path, content))

        return findings
