from __future__ import annotations

import re
from pathlib import Path

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import (
    find_suspicious_terms_in_text,
    text_contains_base64_decode_pipeline,
)
from security_scanner.parsers import analyze_js_code_with_ast, analyze_python_code_ast
from security_scanner.signatures.command_signatures import COMMAND_SIGNATURES


class CommandInjectionDetector:
    FINDING_INDEX = [0]

    @staticmethod
    def _next_id() -> str:
        CommandInjectionDetector.FINDING_INDEX[0] += 1
        return generate_finding_id("command_injection", CommandInjectionDetector.FINDING_INDEX[0])

    def detect_eval_patterns(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect eval/exec patterns"""
        findings = []
        eval_patterns = [
            (r"\beval\s*\(", "eval() - execucao de codigo arbitrario"),
            (r"\bexec\s*\(", "exec() - execucao de comando"),
            (r"\bcompile\s*\(", "compile() - compilacao de codigo"),
            (r"\bmarshal\.(?:load|loads)\(", "marshal.load - desserializacao perigosa"),
            (r"\bpickle\.(?:load|loads)\(", "pickle.load - desserializacao perigosa"),
            (r"\bdill\.(?:load|loads)\(", "dill.load - desserializacao perigosa"),
            (r"\bctypes\.(?:CDLL|WinDLL|CDLL|LibraryLoader)\(", "ctypes - carregamento de biblioteca nativa"),
            (r"\bos\.system\s*\(", "os.system() - execucao de comando shell"),
            (r"\bos\.popen\s*\(", "os.popen() - execucao de comando"),
            (r"\bsubprocess\.(?:Popen|call|run|check_call|check_output)\s*\(", "subprocess - execucao de comando"),
            (r"\bsocket\.(?:socket|create_connection|connect)\s*\(", "socket - comunicacao de rede"),
            (r"\s__import__\s*\(", "__import__() - import dinamico"),
            (r"\bglobals\(\)\s*\[|locals\(\)\s*\[", "globals/locals abuse - manipulacao de escopo"),
            (r"monkey_patch|monkeypatch", "Monkey patching - possivel hijacking de funcao"),
        ]
        for pat, desc in eval_patterns:
            if re.search(pat, content):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:300],
                    category="command_injection",
                    description=f"Padrao de injecao de comando: {desc}",
                    recommendation="Evite execucao dinamica de codigo. Prefira funcoes seguras.",
                    detected_terms=[pat.split("\\")[0].strip("r^$.?*+{}[]\\|()")[:20]],
                ))
        return findings

    def detect_js_dangerous(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect dangerous JS patterns"""
        findings = []
        js_patterns = [
            (r"child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(", "child_process exec/spawn/fork"),
            (r"Function\s*\([\"'\s]*return", "Function() constructor - criacao dinamica de funcao"),
            (r"eval\s*\(", "eval()"),
            (r"Buffer\.from\s*\([^,]+,\s*['\"]base64['\"]", "Buffer.from base64 decode"),
            (r"process\.env\[\w+\]", "Acesso a process.env"),
            (r"require\s*\(['\"]child_process['\"]", "require child_process"),
            (r"fs\.(?:writeFile|writeFileSync|appendFile|chmod)\s*\(", "fs file operations"),
            (r"net\.connect\s*\(|dns\.resolve\s*\(|dns\.lookup\s*\(", "network access via net/dns"),
        ]
        for pat, desc in js_patterns:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:300],
                    category="command_injection",
                    description=f"Padrao JavaScript perigoso: {desc}",
                    recommendation="Audite chamadas perigosas em JavaScript/TypeScript.",
                    detected_terms=[desc.split(" - ")[0][:20]],
                ))
        return findings

    def detect_deserialization(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect dangerous deserialization patterns"""
        findings = []
        patterns = [
            (r"pickle\.(?:load|loads)\s*\(", "Python pickle desserializacao - RCE via dados maliciosos"),
            (r"yaml\.(?:load|loads)\s*\([^)]*\)", "YAML load sem SafeLoader - possivel RCE"),
            (r"jsonpickle\.(?:decode|loads)\s*\(", "jsonpickle desserializacao - RCE"),
            (r"python\.name\s*\(['\"]\w+['\"]\)", "Possivel desserializacao remota"),
        ]
        content_lower = content.lower()
        for pat, desc in patterns:
            if re.search(pat, content):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:200],
                    category="command_injection",
                    description=desc,
                    recommendation="Use safe_load ou equivalentes. Evite desserializacao de dados nao confiaveis.",
                    detected_terms=["deserialization"],
                ))
        return findings

    def detect_node_options_injection(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 8: NODE_OPTIONS injection"""
        findings = []
        match = re.search(r'NODE_OPTIONS\s*=\s*["\']?([^"\'\n]+)', content)
        if match and ("--require" in match.group(1) or "--experimental-loader" in match.group(1)):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=80.0,
                file_path=file_path, evidence=match.group(0)[:200],
                category="command_injection",
                description="NODE_OPTIONS com --require ou --experimental-loader - injecao de codigo no Node.js.",
                recommendation="Remova flags perigosas de NODE_OPTIONS.",
                detected_terms=["NODE_OPTIONS injection"],
            ))
        return findings

    def detect_malicious_import(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Detect dynamic/malicious imports"""
        findings = []
        patterns = [
            (r"__import__\s*\(\s*['\"]", "Import dinamico via __import__()"),
            (r"importlib\.import_module\s*\(", "Import dinamico via importlib"),
            (r"exec\(.*import", "Import dentro de exec - possivel ofuscacao"),
        ]
        for pat, desc in patterns:
            if re.search(pat, content):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=55.0,
                    file_path=file_path, evidence=content[:200],
                    category="command_injection",
                    description=desc,
                    recommendation="Evite imports dinamicos quando possivel.",
                    detected_terms=["dynamic import"],
                ))
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        ext = file_path.suffix.lower()

        if ext == ".py":
            findings.extend(self.detect_eval_patterns(file_path, content))
            findings.extend(self.detect_deserialization(file_path, content))
            findings.extend(self.detect_malicious_import(file_path, content))
            ast_findings = analyze_python_code_ast(content)
            if ast_findings:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence="; ".join(ast_findings),
                    category="command_injection",
                    description=f"AST analysis detectou chamadas perigosas em Python.",
                    recommendation="Audite as chamadas perigosas no codigo Python.",
                    detected_terms=ast_findings,
                ))

        if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            findings.extend(self.detect_js_dangerous(file_path, content))
            ast_findings = analyze_js_code_with_ast(content)
            if ast_findings:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence="; ".join(ast_findings),
                    category="command_injection",
                    description=f"AST analysis detectou chamadas perigosas em JavaScript.",
                    recommendation="Audite as chamadas perigosas no codigo JavaScript.",
                    detected_terms=ast_findings,
                ))

        findings.extend(self.detect_node_options_injection(file_path, content))
        return findings
