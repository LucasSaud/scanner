from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import find_suspicious_terms_in_text
from security_scanner.parsers import parse_jsonc_file, parse_yaml_file, HAS_YAML
from security_scanner.config import config


class IDEPoisoningDetector:
    def __init__(self):
        self._finding_index = 0

    def _next_id(self) -> str:
        self._finding_index += 1
        return generate_finding_id("ide_poisoning", self._finding_index)

    def detect_obfuscated_tasks(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 65: VSCode obfuscated tasks"""
        findings = []
        try:
            data = __import__("json").loads(content)
        except Exception:
            data = None
        if not data:
            return findings
        for task in data.get("tasks", []):
            label = task.get("label", "unnamed")
            run_on = task.get("runOptions", {}).get("runOn", "")
            fields = ("command", "args", "type", "script", "shell")
            task_text = " ".join(str(task.get(f, "")) for f in fields)
            lower = task_text.lower()
            terms = find_suspicious_terms_in_text(lower)
            auto_exec = run_on == "folderOpen"
            if auto_exec and terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL", score=95.0,
                    file_path=file_path, evidence=task_text[:400],
                    category="ide_poisoning", line=task.get("__line", 0),
                    description=f"VSCode task '{label}' executa automaticamente ao abrir pasta e contem comandos perigosos.",
                    recommendation="Remova a task maliciosa ou desabilite execucao automatica (runOn).",
                    detected_terms=terms,
                ))
            elif auto_exec:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=task_text[:400],
                    category="ide_poisoning",
                    description=f"VSCode task '{label}' executa automaticamente ao abrir pasta.",
                    recommendation="Verifique se a task e legitima. Tasks com runOn=folderOpen executam sem interacao.",
                ))
            elif terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=50.0,
                    file_path=file_path, evidence=task_text[:400],
                    category="ide_poisoning",
                    description=f"VSCode task '{label}' contem termos suspeitos.",
                    recommendation="Audite a task.",
                    detected_terms=terms,
                ))
        return findings

    def detect_security_override(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 66: VSCode security override"""
        findings = []
        data = parse_jsonc_file(file_path)
        if not data:
            return findings
        dangerous = config.dangerous_vscode_settings
        for key in dangerous:
            if key in data:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=f"{key}: {data[key]}",
                    category="ide_poisoning",
                    description=f"settings.json redefine '{key}' - pode redirecionar executavel.",
                    recommendation="Remova ou verifique a configuracao - pode redirecionar terminal/interpretador.",
                    detected_terms=[key],
                ))
        return findings

    def detect_debugger_exposure(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 67: VSCode debugger exposure"""
        findings = []
        data = parse_jsonc_file(file_path)
        if not data:
            return findings
        for config_ in data.get("configurations", []):
            if isinstance(config_, dict):
                name = config_.get("name", "unnamed")
                runtime = str(config_.get("runtimeExecutable", ""))
                if runtime:
                    terms = find_suspicious_terms_in_text(runtime.lower())
                    if terms:
                        findings.append(DetectionFinding(
                            id=self._next_id(), severity="HIGH", score=70.0,
                            file_path=file_path, evidence=f"{name}: {runtime}",
                            category="ide_poisoning",
                            description=f"Debug config '{name}' aponta para executavel suspeito.",
                            recommendation="Audite runtimeExecutable no launch.json.",
                            detected_terms=terms,
                        ))
        return findings

    def detect_devcontainer_commands(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 68: devcontainer post commands"""
        findings = []
        try:
            data = __import__("json").loads(content)
        except Exception:
            data = None
        if not data:
            return findings
        auto_keys = config.devcontainer_auto_keys
        for key in auto_keys:
            cmd = str(data.get(key, "")).lower()
            if not cmd:
                continue
            terms = find_suspicious_terms_in_text(cmd)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="CRITICAL", score=90.0,
                    file_path=file_path, evidence=f"{key}: {cmd[:300]}",
                    category="ide_poisoning",
                    description=f"devcontainer.json '{key}' executa automaticamente com comandos perigosos.",
                    recommendation="Remova comandos perigosos do devcontainer. Estes comandos executam sem interacao.",
                    detected_terms=terms,
                ))
        return findings

    def detect_devcontainer_mounts(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 69: devcontainer sensitive mounts"""
        findings = []
        try:
            data = __import__("json").loads(content)
        except Exception:
            return findings
        mounts = data.get("mounts", []) if isinstance(data.get("mounts"), list) else []
        sensitive_paths = ["/root/.ssh", "/root/.aws", "/var/run/docker.sock", "/etc/shadow", "/etc/passwd", "/etc/sudoers"]
        for mount in mounts:
            if isinstance(mount, str) and any(p in mount for p in sensitive_paths):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=mount,
                    category="ide_poisoning",
                    description=f"Devcontainer monta volume sensivel: {mount}",
                    recommendation="Remova mounts de diretorios sensiveis no devcontainer.json.",
                    detected_terms=["sensitive mount"],
                ))
        return findings

    def detect_jupyter_miners(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 70: Jupyter extension miners"""
        findings = []
        data = parse_jsonc_file(file_path)
        if not data:
            return findings
        recommendations = data.get("recommendations", [])
        MINER_EXTENSIONS = ["ms-python.python", "ms-toolsai.jupyter"]
        for rec in recommendations:
            if isinstance(rec, str) and rec not in MINER_EXTENSIONS:
                terms = find_suspicious_terms_in_text(rec.lower())
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=70.0,
                        file_path=file_path, evidence=f"recommendation: {rec}",
                        category="ide_poisoning",
                        description=f"Extensao recomendada suspeita: {rec} - possivel minerador.",
                        recommendation="Verifique a extensao no Marketplace antes de instalar.",
                        detected_terms=["suspicious extension"],
                    ))
        return findings

    def detect_jetbrains_workspace(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 56: JetBrains workspace execution"""
        findings = []
        if file_path.suffix in (".iml", ".ipr"):
            if "application" in content.lower() and "exec" in content.lower():
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="ide_poisoning",
                    description="Arquivo de projeto JetBrains com configuracao de execucao externa.",
                    recommendation="Audite configuracoes de execucao no workspace do JetBrains.",
                    detected_terms=["jetbrains workspace"],
                ))
        return findings

    def detect_jetbrains_background(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 57: JetBrains background tasks"""
        findings = []
        if "tasks" in content.lower() and file_path.suffix == ".xml":
            terms = find_suspicious_terms_in_text(content.lower())
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="ide_poisoning",
                    description="JetBrains tasks configuration com termos suspeitos - tasks rodam em background.",
                    recommendation="Audite as tasks do JetBrains no diretorio .idea/.",
                    detected_terms=terms,
                ))
        return findings

    def detect_cursor_prompt(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 58: Cursor/Cline prompt injection"""
        findings = []
        if ".cursorrules" in str(file_path) or "cursor" in str(file_path).lower():
            suspicious = [t for t in ["ignore", "always", "never", "override", "inject"] if t in content.lower()]
            if len(suspicious) >= 2:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=50.0,
                    file_path=file_path, evidence=content[:400],
                    category="ide_poisoning",
                    description="Possivel prompt injection em configuracao Cursor/Cline - instrucoes que manipulam o comportamento do AI.",
                    recommendation="Verifique se as regras sao legítimas. Prompts maliciosos podem injetar comandos via AI.",
                    detected_terms=["prompt injection", "cursor"],
                ))
        return findings

    def detect_sublime_build(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 60: Sublime build execution"""
        findings = []
        if file_path.suffix == ".sublime-build":
            terms = find_suspicious_terms_in_text(content.lower())
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="ide_poisoning",
                    description="Sublime Text build system contem comandos perigosos - executa ao compilar.",
                    recommendation="Audite o build system do Sublime.",
                    detected_terms=terms,
                ))
        return findings

    def detect_neovim_autoexec(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 62: Neovim init.lua autoexec"""
        findings = []
        if file_path.name in ("init.lua", "init.vim", ".vimrc", "init.lua"):
            dangerous = ["vim.cmd(", "vim.api.nvim_exec(", "os.execute(", "io.popen(", "luaeval("]
            detected = [d for d in dangerous if d.lower() in content.lower()]
            if detected:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:400],
                    category="ide_poisoning",
                    description=f"Neovim init contem execucao de comando: {detected}",
                    recommendation="Audite o arquivo de configuracao do Neovim - executa ao iniciar o editor.",
                    detected_terms=detected,
                ))
        return findings

    def detect_msbuild(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 64: MSBuild execution"""
        findings = []
        if file_path.suffix in (".csproj", ".vbproj", ".fsproj", ".targets"):
            if re.search(r"Exec\s+|ExecCommand|MSBuild\.Execute", content, re.IGNORECASE):
                terms = find_suspicious_terms_in_text(content.lower())
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=content[:400],
                        category="ide_poisoning",
                        description="Projeto MSBuild contem execucao de comandos - executa durante build.",
                        recommendation="Audite targets e comandos no arquivo de projeto MSBuild.",
                        detected_terms=terms,
                    ))
        return findings

    def detect_vscode_snippets(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """General: VSCode snippet injection"""
        findings = []
        if file_path.suffix == ".code-snippets":
            data = parse_jsonc_file(file_path)
            if data:
                for snippet_name, snippet in data.items():
                    if isinstance(snippet, dict):
                        body = snippet.get("body", "")
                        if isinstance(body, list):
                            body = " ".join(str(b) for b in body)
                        if isinstance(body, str) and find_suspicious_terms_in_text(body.lower()):
                            findings.append(DetectionFinding(
                                id=self._next_id(), severity="HIGH", score=70.0,
                                file_path=file_path, evidence=body[:300],
                                category="ide_poisoning",
                                description=f"VSCode snippet '{snippet_name}' contem termos suspeitos.",
                                recommendation="Audite snippets do VSCode - inserem texto automaticamente.",
                                detected_terms=find_suspicious_terms_in_text(body.lower()),
                            ))
        return findings

    def detect_keybindings(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """General: VSCode keybinding injection"""
        findings = []
        data = parse_jsonc_file(file_path)
        if not data:
            return findings
        bindings = data if isinstance(data, list) else data.get("keybindings", data)
        if not isinstance(bindings, list):
            return findings
        for idx, binding in enumerate(bindings):
            if not isinstance(binding, dict):
                continue
            command = binding.get("command", "")
            args = binding.get("args", {})
            key = binding.get("key", f"binding {idx}")
            if "terminal.sendSequence" in command or "shellCommand" in command:
                args_text = str(args).lower()
                terms = find_suspicious_terms_in_text(args_text)
                sev = "HIGH" if terms else "MEDIUM"
                findings.append(DetectionFinding(
                    id=self._next_id(), severity=sev, score=75.0 if terms else 50.0,
                    file_path=file_path, evidence=f"key: {key} | cmd: {command} | args: {args}",
                    category="ide_poisoning",
                    description=f"Keybinding '{key}' com comando '{command}' - pode enviar comandos ao terminal.",
                    recommendation="Audite keybindings com terminal.sendSequence ou shellCommand.",
                    detected_terms=terms or [],
                ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        name = file_path.name.lower()
        parent = file_path.parent.name.lower()

        if name == "tasks.json" and parent == ".vscode":
            findings.extend(self.detect_obfuscated_tasks(file_path, content))
        if name == "settings.json" and parent == ".vscode":
            findings.extend(self.detect_security_override(file_path, content))
        if name == "launch.json" and parent == ".vscode":
            findings.extend(self.detect_debugger_exposure(file_path, content))
        if name == "extensions.json" and parent == ".vscode":
            findings.extend(self.detect_jupyter_miners(file_path, content))
        if name == "keybindings.json" and parent == ".vscode":
            findings.extend(self.detect_keybindings(file_path, content))
        if name.endswith(".code-snippets"):
            findings.extend(self.detect_vscode_snippets(file_path, content))
        if "devcontainer" in name and parent == ".devcontainer":
            findings.extend(self.detect_devcontainer_commands(file_path, content))
            findings.extend(self.detect_devcontainer_mounts(file_path, content))

        if file_path.suffix in (".iml", ".ipr"):
            findings.extend(self.detect_jetbrains_workspace(file_path, content))
        if parent == ".idea" and file_path.suffix == ".xml":
            findings.extend(self.detect_jetbrains_background(file_path, content))
        if ".cursorrules" in str(file_path):
            findings.extend(self.detect_cursor_prompt(file_path, content))
        if file_path.suffix == ".sublime-build":
            findings.extend(self.detect_sublime_build(file_path, content))
        if file_path.name in ("init.lua", "init.vim", ".vimrc"):
            findings.extend(self.detect_neovim_autoexec(file_path, content))
        if file_path.suffix in (".csproj", ".vbproj", ".fsproj", ".targets"):
            findings.extend(self.detect_msbuild(file_path, content))

        return findings
