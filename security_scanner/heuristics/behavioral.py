from __future__ import annotations

import re
from typing import Optional


class BehavioralAnalyzer:
    PIPELINE_PATTERNS: list[tuple[str, str, float, str]] = [
        (r"curl\s+[^\n]*\|\s*bash", "download_and_execute_bash", 95.0, "CRITICAL"),
        (r"curl\s+[^\n]*\|\s*sh", "download_and_execute_sh", 95.0, "CRITICAL"),
        (r"wget\s+[^\n]*\|\s*bash", "download_and_execute_wget_bash", 95.0, "CRITICAL"),
        (r"curl\s+[^\n]*\|\s*python", "download_and_execute_python", 90.0, "CRITICAL"),
        (r"curl\s+[^\n]*\|\s*node", "download_and_execute_node", 90.0, "CRITICAL"),
        (r"base64\s*-d\s*\|.*bash", "decode_and_execute", 85.0, "HIGH"),
        (r"echo\s+[A-Za-z0-9+/=]{30,}\s*\|.*base64.*\|.*bash", "echo_decode_execute", 95.0, "CRITICAL"),
        (r"git\s+clone\s+[^\s]+\s*&&\s*(?:bash|sh)\s", "clone_and_execute", 90.0, "CRITICAL"),
        (r"npm\s+install.*&&.*(?:curl|wget|bash)", "npm_install_and_execute", 85.0, "HIGH"),
        (r"pip\s+install.*&&.*(?:curl|wget|bash)", "pip_install_and_execute", 85.0, "HIGH"),
        (r"(?:sudo|su)\s+(?:bash|sh|zsh)\s+-c\s+['\"](?:curl|wget)", "sudo_download_execute", 95.0, "CRITICAL"),
        (r"(?:chmod\+x|chmod\s+777)\s+.*&&\s*\./", "make_executable_and_run", 75.0, "HIGH"),
        (r"(?:dd|cat)\s+.*>\s*.*\.(?:sh|py|pl|rb)\s*&&\s*(?:bash|sh|python|perl|ruby)", "write_script_and_execute", 85.0, "HIGH"),
    ]

    CHAIN_PATTERNS: list[tuple[str, str, float, str]] = [
        (r"(?:curl|wget).*(?:bash|sh|zsh).*(?:base64|eval)", "download_shell_encode_chain", 98.0, "CRITICAL"),
        (r"(?:eval|exec).*(?:curl|wget).*(?:bash|sh)", "eval_download_chain", 98.0, "CRITICAL"),
        (r"(?:cron|at|systemd).*(?:curl|wget|bash|python)", "scheduled_download_chain", 90.0, "CRITICAL"),
        (r"LD_PRELOAD.*(?:curl|wget|bash)", "ld_preload_download_chain", 95.0, "CRITICAL"),
        (r"(?:rc\.local|bashrc|zshrc|profile).*(?:curl|wget|bash)", "rc_download_chain", 90.0, "HIGH"),
        (r"(?:git hooks|post-commit|pre-commit|post-checkout).*(?:curl|wget|bash)", "hook_download_chain", 95.0, "CRITICAL"),
        (r"(?:Dockerfile|docker-compose).*curl.*bash", "dockerfile_download_chain", 95.0, "CRITICAL"),
        (r"(?:package\.json|postinstall|preinstall).*(?:curl|wget|bash)", "npm_hook_download_chain", 95.0, "CRITICAL"),
        (r"(?:setup\.py|tox\.ini|pyproject).*curl.*bash", "python_build_download_chain", 90.0, "CRITICAL"),
    ]

    def analyze_pipelines(self, text: str) -> list[dict]:
        findings = []
        for pattern, name, score, severity in self.PIPELINE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({
                    "name": name, "score": score, "severity": severity,
                    "pattern": pattern, "category": "pipeline",
                })
        return findings

    def analyze_chains(self, text: str) -> list[dict]:
        findings = []
        for pattern, name, score, severity in self.CHAIN_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({
                    "name": name, "score": score, "severity": severity,
                    "pattern": pattern, "category": "chain",
                })
        return findings

    def analyze(self, text: str) -> dict:
        return {
            "pipelines": self.analyze_pipelines(text),
            "chains": self.analyze_chains(text),
            "total_pipelines": 0,
            "total_chains": 0,
        }
