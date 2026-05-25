from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import find_suspicious_terms_in_text
from security_scanner.parsers import analyze_python_code_ast
from security_scanner.config import config
from security_scanner.signatures.shell_signatures import SHELL_DANGEROUS_PATTERNS
from security_scanner.signatures.regex_signatures import PERSISTENCE_PATTERNS


class PersistenceDetector:
    def __init__(self):
        self._finding_index = 0

    def _next_id(self) -> str:
        self._finding_index += 1
        return generate_finding_id("persistence", self._finding_index)

    # ── Git Persistence ──────────────────────────────────────────────────

    def detect_git_hook_malicious(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 54: obfuscated bash hooks"""
        findings = []
        text = content.lower()
        terms = find_suspicious_terms_in_text(text)
        has_base64 = "base64" in text
        has_remote = any(t in text for t in ["curl", "wget", "fetch", "http://", "https://"])
        if terms or has_base64:
            sev = "CRITICAL" if has_base64 and has_remote else "HIGH"
            score_val = 90.0 if has_base64 else 75.0
            findings.append(DetectionFinding(
                id=self._next_id(), severity=sev, score=score_val,
                file_path=file_path, evidence=content[:400],
                category="persistence",
                description=f"Git hook '{file_path.name}' contem comandos suspeitos.",
                recommendation="Remova o hook malicioso do diretorio .git/hooks/.",
                detected_terms=terms,
            ))
        return findings

    def detect_gitattributes_filter(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 41: gitattributes filters"""
        findings = []
        if re.search(r"filter\s+\w+\s+", content, re.IGNORECASE):
            match = re.search(r"filter\s+(\w+)\s+", content, re.IGNORECASE)
            filter_name = match.group(1) if match else "unknown"
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=75.0,
                file_path=file_path, evidence=content[:400],
                category="persistence",
                description=f"Git filter '{filter_name}' definido em .gitattributes - pode executar no checkout/commit via clean/smudge.",
                recommendation="Audite os filters no .gitattributes. Filters executam automaticamente.",
                detected_terms=["git filter"],
            ))
        return findings

    def detect_git_editor(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 42: git editor hijacking"""
        findings = []
        if "editor" in content.lower() or "core.pager" in content.lower():
            match = re.search(r"(?:editor|pager)\s*=\s*(.+)", content)
            if match and match.group(1).strip() not in ("vim", "nano", "emacs", "code", "vi"):
                val = match.group(1).strip()
                terms = find_suspicious_terms_in_text(val.lower())
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=80.0,
                        file_path=file_path, evidence=f"editor/pager = {val}",
                        category="persistence",
                        description=f"Git config redireciona editor/pager para: {val}",
                        recommendation="Use apenas editores conhecidos (vim, nano, code).",
                        detected_terms=terms,
                    ))
        return findings

    def detect_git_aliases(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 48: malicious git aliases"""
        findings = []
        for match in re.finditer(r'\[alias\]\s*\n(.*?)(?=\n\[|$)', content, re.DOTALL):
            alias_section = match.group(1)
            for alias_line in alias_section.split("\n"):
                if "=" in alias_line:
                    alias_cmd = alias_line.split("=", 1)[1].strip()
                    terms = find_suspicious_terms_in_text(alias_cmd.lower())
                    if terms:
                        findings.append(DetectionFinding(
                            id=self._next_id(), severity="HIGH", score=70.0,
                            file_path=file_path, evidence=alias_line.strip(),
                            category="persistence",
                            description=f"Alias git malicioso detectado: {alias_line.strip()}",
                            recommendation="Remova aliases git que executam comandos externos.",
                            detected_terms=terms,
                        ))
        return findings

    def detect_hookspath_redirect(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 50: hooksPath redirect"""
        findings = []
        if "hooksPath" in content:
            match = re.search(r"hooksPath\s*=\s*(.+)", content)
            if match:
                path = match.group(1).strip()
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=f"hooksPath = {path}",
                    category="persistence",
                    description=f"Git hooksPath redirecionado para: {path} - pode executar hooks de local externo.",
                    recommendation="Nao use hooksPath em repositorios nao confiaveis.",
                    detected_terms=["hooksPath redirect"],
                ))
        return findings

    def detect_gpg_bypass(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 53: weak/fake GPG signatures"""
        findings = []
        text = content.lower()
        if "gpgsign" in text and "gpg.format" in text:
            if "ssh" in text:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=45.0,
                    file_path=file_path, evidence=content[:300],
                    category="persistence",
                    description="Git configurado com gpg.format=ssh - possivel bypass de verificacao deassinatura.",
                    recommendation="Use GPG keys proprias para assinatura de commits.",
                    detected_terms=["gpg bypass"],
                ))
        return findings

    # ── Shell Persistence ────────────────────────────────────────────────

    def detect_rc_abuse(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 87: local bashrc/zshrc"""
        findings = []
        if file_path.name in (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".config/fish/config.fish"):
            text = content.lower()
            terms = find_suspicious_terms_in_text(text)
            has_alias = "alias" in text
            has_path = "export path" in text or "set path" in text or "set -gx" in text
            if terms:
                sev = "HIGH" if has_alias or has_path else "MEDIUM"
                findings.append(DetectionFinding(
                    id=self._next_id(), severity=sev, score=75.0 if has_alias else 55.0,
                    file_path=file_path, evidence=content[:400],
                    category="persistence",
                    description=f"Arquivo RC '{file_path.name}' contem termos suspeitos - executa ao iniciar shell.",
                    recommendation="Audite RC files - executam em todo novo shell.",
                    detected_terms=terms,
                ))
        return findings

    def detect_direnv_rce(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 88: direnv RCE"""
        findings = []
        if file_path.name == ".envrc":
            text = content.lower()
            terms = find_suspicious_terms_in_text(text)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=content[:400],
                    category="persistence",
                    description=".envrc contem comandos perigosos - executa automaticamente ao entrar no diretorio.",
                    recommendation="Audite .envrc - direnv executa o conteudo automaticamente.",
                    detected_terms=terms,
                ))
        return findings

    def detect_alias_hijack(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 93: alias hijacking"""
        findings = []
        for match in re.finditer(r'alias\s+(\w+)\s*=\s*["\']([^"\']+)["\']', content):
            alias_name = match.group(1)
            alias_cmd = match.group(2).lower()
            if alias_name in ("curl", "wget", "ssh", "git", "sudo", "npm", "pip", "python", "bash"):
                if alias_name.lower() not in alias_cmd:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=80.0,
                        file_path=file_path, evidence=match.group(0),
                        category="persistence",
                        description=f"Alias hijacking: '{alias_name}' redirecionado para '{alias_cmd[:60]}'",
                        recommendation=f"Remova o alias malicioso de {alias_name}.",
                        detected_terms=[f"alias hijack: {alias_name}"],
                    ))
        return findings

    def detect_history_wipe(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 92: history wiping"""
        findings = []
        patterns = [r"history\s+-c", r">?\s*~/\..*history", r"unset\s+HISTFILE", r"export\s+HISTSIZE=0"]
        for pat in patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=50.0,
                    file_path=file_path, evidence=content[:200],
                    category="persistence",
                    description="Comando de limpeza de historico detectado - possivel encobrimento de atividades.",
                    recommendation="Investigue porque o historico esta sendo limpo.",
                    detected_terms=["history wipe"],
                ))
                break
        return findings

    def detect_cron_persistence(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 94: cron persistence"""
        findings = []
        if "crontab" in content.lower() or "@reboot" in content:
            text = content.lower()
            if any(t in text for t in ["curl", "wget", "bash", "python", "sh"]):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL", score=90.0,
                    file_path=file_path, evidence=content[:400],
                    category="persistence",
                    description="Cron job com execucao remota detectado - persistencia com payload externo.",
                    recommendation="Remova o cron job malicioso. Verifique crontab -l.",
                    detected_terms=["cron persistence"],
                ))
        return findings

    def detect_systemd_persistence(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 95: systemd persistence"""
        findings = []
        if file_path.suffix == ".service" and "systemd" in str(file_path):
            lower = content.lower()
            if any(t in lower for t in ["curl", "wget", "bash", "python", "execstart="]):
                terms = find_suspicious_terms_in_text(lower)
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="CRITICAL", score=90.0,
                        file_path=file_path, evidence=content[:400],
                        category="persistence",
                        description="Unidade systemd contem execucao de comandos - possivel persistencia.",
                        recommendation="Audite unidades systemd em /etc/systemd/system/ e ~/.config/systemd/.",
                        detected_terms=terms,
                    ))
        return findings

    def detect_tmux_persistence(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 89: tmux persistence"""
        findings = []
        if file_path.name == ".tmux.conf":
            text = content.lower()
            if "run-shell" in text or "if-shell" in text:
                terms = find_suspicious_terms_in_text(text)
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="MEDIUM", score=55.0,
                        file_path=file_path, evidence=content[:300],
                        category="persistence",
                        description="Configuracao tmux contem execucao de comandos - executa ao iniciar tmux.",
                        recommendation="Audite .tmux.conf para comandos run-shell.",
                        detected_terms=terms,
                    ))
        return findings

    def detect_applescript(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 90: AppleScript wrappers"""
        findings = []
        if file_path.suffix == ".applescript" or file_path.suffix == ".scpt":
            lower = content.lower()
            terms = find_suspicious_terms_in_text(lower)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="persistence",
                    description="AppleScript contem comandos shell - pode executar comandos no sistema.",
                    recommendation="Audite AppleScripts que executam shell commands.",
                    detected_terms=terms,
                ))
        return findings

    def detect_clean_smudge(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 55: clean/smudge hijacking"""
        findings = []
        if "filter" in content.lower():
            for match in re.finditer(r'\[filter\s+"(\w+)"\]', content):
                filter_name = match.group(1)
                if filter_name:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=match.group(0),
                        category="persistence",
                        description=f"Git filter '{filter_name}' definido em .git/config - clean/smudge executam automaticamente.",
                        recommendation="Audite filters do git - clean/smudge rodam em checkout/commit.",
                        detected_terms=["clean/smudge hijack"],
                    ))
        return findings

    def detect_ssh_command(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """sshCommand hijacking"""
        findings = []
        if "sshCommand" in content:
            match = re.search(r"sshCommand\s*=\s*(.+)", content)
            if match:
                val = match.group(1).strip()
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=f"sshCommand = {val}",
                    category="persistence",
                    description=f"Git sshCommand redirecionado para: {val} - executa ao fazer git clone/push/pull via SSH.",
                    recommendation="Nao use sshCommand em repositorios nao confiaveis.",
                    detected_terms=["sshCommand hijack"],
                ))
        return findings

    def detect_submodule_trap(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 44: submodule traps"""
        findings = []
        if file_path.name == ".gitmodules":
            for match in re.finditer(r"url\s*=\s*(.+)", content):
                url = match.group(1).strip()
                if url.startswith("http://") or re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=url,
                        category="persistence",
                        description=f"Submodule URL nao segura: {url[:80]} - possivel submodule trap.",
                        recommendation="Use URLs HTTPS com dominio confiavel para submodules.",
                        detected_terms=["submodule trap"],
                    ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        name = file_path.name
        parent = str(file_path.parent)

        # Git hooks
        if ".git/hooks/" in parent and not file_path.suffix:
            findings.extend(self.detect_git_hook_malicious(file_path, content))

        # Git config
        if name == "config" and ".git" in parent:
            findings.extend(self.detect_git_editor(file_path, content))
            findings.extend(self.detect_git_aliases(file_path, content))
            findings.extend(self.detect_hookspath_redirect(file_path, content))
            findings.extend(self.detect_gpg_bypass(file_path, content))
            findings.extend(self.detect_clean_smudge(file_path, content))
            findings.extend(self.detect_ssh_command(file_path, content))

        # Git attributes
        if name == ".gitattributes":
            findings.extend(self.detect_gitattributes_filter(file_path, content))

        # Git submodules
        if name == ".gitmodules":
            findings.extend(self.detect_submodule_trap(file_path, content))

        # Shell RC
        if name in (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile"):
            findings.extend(self.detect_rc_abuse(file_path, content))
            findings.extend(self.detect_alias_hijack(file_path, content))
            findings.extend(self.detect_history_wipe(file_path, content))

        # direnv
        if name == ".envrc":
            findings.extend(self.detect_direnv_rce(file_path, content))

        # tmux
        if name == ".tmux.conf":
            findings.extend(self.detect_tmux_persistence(file_path, content))

        # cron/systemd
        if "cron" in name.lower() or "crontab" in name.lower():
            findings.extend(self.detect_cron_persistence(file_path, content))
        if file_path.suffix == ".service" and "systemd" in str(file_path):
            findings.extend(self.detect_systemd_persistence(file_path, content))

        # AppleScript
        if file_path.suffix in (".applescript", ".scpt"):
            findings.extend(self.detect_applescript(file_path, content))

        return findings
