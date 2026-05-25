from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from security_scanner.models import DetectionFinding, generate_finding_id
from security_scanner.utils.text_utils import (
    find_suspicious_terms_in_text,
    text_contains_base64_decode_pipeline,
    detect_js_join_obfuscation,
    detect_high_entropy_content,
    normalize_text_recursive,
)
from security_scanner.parsers import parse_jsonc_file, parse_yaml_file, analyze_js_code_with_ast, HAS_YAML
from security_scanner.heuristics.scoring import RiskScorer, ScoreModifier
from security_scanner.signatures.ioc_signatures import IOCDatabase
from security_scanner.config import config

ioc_db = IOCDatabase()
npm_hooks = config.npm_auto_hooks


class SupplyChainDetector:
    def __init__(self):
        self._finding_index = 0

    def _next_id(self, category: str = "supply_chain") -> str:
        self._finding_index += 1
        return generate_finding_id(category, self._finding_index)

    # ── npm ──────────────────────────────────────────────────────────────

    def detect_npmrc_hijacking(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 1: npmrc registry hijacking"""
        findings = []
        lower = content.lower()
        match = re.search(r"registry\s*=\s*(https?://[^\s]+)", content)
        if match:
            url = match.group(1)
            if "registry.npmjs.org" not in url and "registry.yarnpkg.com" not in url:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=url,
                    category="supply_chain", line=content[:200].count("\n") + 1,
                    description=f".npmrc/.yarnrc redireciona registry para URL externa: {url[:60]}",
                    recommendation="Use apenas registros oficiais (registry.npmjs.org). Verifique se o registro é confiável.",
                    detected_terms=["registry hijack"],
                ))
        return findings

    def detect_typosquatting(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 2: Typosquatting package.json"""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return findings
        all_deps = {}
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            all_deps.update(data.get(section, {}))
        TYPOSQUAT_TARGETS = {
            "event-stream": "event-stream", "cross-env": "cross-env",
            "crossenv": "cross-env", "babel-cli": "babel-cli",
            "babelclie": "babel-cli", "babelcli": "babel-cli",
            "babel-node": "babel-node", "babelnode": "babel-node",
            "express": "express", "expresss": "express",
            "gulb": "gulp", "gulp": "gulp",
            "grunt": "grunt", "grunnt": "grunt",
            "webpack": "webpack", "webpackp": "webpack",
            "react": "react", "reactt": "react",
            "angular": "angular", "angularr": "angular",
            "lodash": "lodash", "lodashh": "lodash",
            "mocha": "mocha", "mochaa": "mocha",
        }
        for dep_name in all_deps:
            if dep_name in TYPOSQUAT_TARGETS and dep_name != TYPOSQUAT_TARGETS[dep_name]:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=f"dependency: {dep_name}",
                    category="supply_chain",
                    description=f"Possível typosquatting: '{dep_name}' é similar a '{TYPOSQUAT_TARGETS[dep_name]}'",
                    recommendation=f"Verifique se '{dep_name}' é o pacote correto ou um typosquatting malicioso.",
                    detected_terms=["typosquatting"],
                ))
        return findings

    def detect_bundled_deps(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 3: bundledDependencies abuse"""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return findings
        bundled = data.get("bundledDependencies") or data.get("bundleDependencies") or []
        if bundled and len(bundled) > 0:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="MEDIUM", score=45.0,
                file_path=file_path, evidence=str(bundled),
                category="supply_chain",
                description="package.json contém bundledDependencies - podem incluir artefatos maliciosos no pacote publicado.",
                recommendation="Audite os pacotes em bundledDependencies. Considere usar apenas dependências do registro.",
                detected_terms=["bundledDependencies"],
            ))
        return findings

    def detect_npm_lifecycle_hooks(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 4: preinstall/postinstall hooks"""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return findings
        scripts = data.get("scripts", {})
        for hook in npm_hooks:
            cmd = scripts.get(hook, "")
            if not cmd:
                continue
            lower = cmd.lower()
            terms = find_suspicious_terms_in_text(lower)
            b64 = text_contains_base64_decode_pipeline(lower)
            js_obfus = detect_js_join_obfuscation(cmd)
            ast = analyze_js_code_with_ast(cmd)
            entropy = detect_high_entropy_content(lower)
            all_signals = [t for t in terms if t not in ("sh", "bash", "zsh")]
            has_remote = any(
                t in lower for t in ["curl", "wget", "fetch", "http://", "https://"]
            )
            has_shell = any(t in lower for t in ["bash", "sh", "zsh", "exec", "eval"])
            all_indicators = all_signals + (["base64_decode"] if b64 else []) + js_obfus + ast

            scorer = RiskScorer(base_score=40.0)
            if has_remote:
                scorer.add_modifier(ScoreModifier.REMOTE_DOWNLOAD)
            if has_shell:
                scorer.add_modifier(ScoreModifier.SHELL_EXECUTION)
            if b64 or js_obfus or ast:
                scorer.add_modifier(ScoreModifier.OBFUSCATION)
            if entropy:
                scorer.add_modifier(ScoreModifier.ENTROPY_HIGH)
            if len(all_indicators) >= 2:
                scorer.add_modifier(ScoreModifier.MULTIPLE_SIGNALS)

            score = min(scorer.calculate(), 100.0)

            if b64 or (has_remote and has_shell) or js_obfus or ast:
                sev = "CRITICAL"
            elif terms and has_shell:
                sev = "HIGH"
            elif terms or entropy:
                sev = "MEDIUM"
            else:
                continue

            desc = f"npm script '{hook}' executa automaticamente"
            if b64 or js_obfus or ast:
                desc += " com ofuscacao detectada"
            elif has_remote and has_shell:
                desc += " com download remoto e execucao shell"
            elif terms:
                desc += " com termos suspeitos"
            if entropy:
                desc += " (alta entropia)"

            findings.append(DetectionFinding(
                id=self._next_id(), severity=sev, score=round(score, 1),
                file_path=file_path, evidence=f"{hook}: {cmd[:300]}",
                category="supply_chain",
                description=desc,
                recommendation="Remova execucao remota de hooks de instalacao. Audite o script do hook.",
                detected_terms=all_indicators,
            ))
        return findings

    def detect_nvmrc_injection(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 5: .nvmrc command injection"""
        findings = []
        stripped = content.strip()
        if stripped and re.search(r"[;|&`$()\[\]{}]", stripped):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=75.0,
                file_path=file_path, evidence=stripped[:200],
                category="supply_chain",
                description=".nvmrc contém caracteres especiais - possível command injection via nvm use.",
                recommendation=".nvmrc deve conter apenas a versão do Node.js, sem comandos.",
                detected_terms=["command injection"],
            ))
        return findings

    def detect_malicious_bin(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 6: malicious bin entries"""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return findings
        bin_entries = data.get("bin", {})
        if isinstance(bin_entries, str):
            bin_entries = {"default": bin_entries}
        for bin_name, bin_path in bin_entries.items():
            if isinstance(bin_path, str):
                terms = find_suspicious_terms_in_text(bin_path.lower())
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=f"bin {bin_name}: {bin_path}",
                        category="supply_chain",
                        description=f"bin entry '{bin_name}' aponta para path suspeito: {bin_path}",
                        recommendation="Audite o bin entry - e executado no PATH do usuario apos npm install -g.",
                        detected_terms=terms,
                    ))
        return findings

    def detect_bin_hijacking(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 7: node_modules/.bin hijacking — only in executable scripts, not docs/READMEs"""
        findings = []
        doc_exts = {".md", ".txt", ".rst", ".adoc"}
        if file_path.suffix.lower() in doc_exts:
            return findings
        if "node_modules/.bin" in content:
            # Only flag if it looks like an active path reference (assignment, execution, shebang)
            if re.search(r'(?:=|["\']|`|^)\s*(?:\./)?node_modules/\.bin/', content, re.MULTILINE):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:200],
                    category="supply_chain",
                    description="Referencia executavel a node_modules/.bin - possivel hijacking de binario de dependencia.",
                    recommendation="Nao referencie node_modules/.bin diretamente. Use npx ou scripts do package.json.",
                    detected_terms=["node_modules/.bin hijacking"],
                ))
        return findings

    def detect_node_options(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 8: NODE_OPTIONS injections"""
        findings = []
        match = re.search(r'NODE_OPTIONS\s*=\s*["\']?([^"\'\n]+)', content)
        if match and any(f in match.group(1) for f in ("--experimental", "--require", "--loader")):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=80.0,
                file_path=file_path, evidence=match.group(0)[:200],
                category="supply_chain",
                description="NODE_OPTIONS definido com flags experimentais/require - possivel injecao de codigo.",
                recommendation="Evite usar --require ou --experimental em NODE_OPTIONS. Audite a configuracao.",
                detected_terms=["NODE_OPTIONS injection"],
            ))
        return findings

    def detect_bunfig_abuse(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 9: bunfig.toml abuse"""
        findings = []
        if "install" in content.lower() and re.search(r'https?://', content):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=70.0,
                file_path=file_path, evidence=content[:200],
                category="supply_chain",
                description="bunfig.toml contem URL externa na configuracao de install - possivel registro malicioso.",
                recommendation="Verifique as fontes de instalacao no bunfig.toml.",
                detected_terms=["bunfig abuse"],
            ))
        return findings

    def detect_deno_import_map(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 10: deno import map hijacking"""
        findings = []
        try:
            data = json.loads(content) if file_path.suffix == ".json" else {}
        except Exception:
            data = {}
        imports = data.get("imports", {}) if isinstance(data, dict) else {}
        for name, url in imports.items():
            if isinstance(url, str) and not url.startswith("https://deno.land") and not url.startswith("https://esm.sh"):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=f"{name}: {url[:100]}",
                    category="supply_chain",
                    description=f"Import map redireciona '{name}' para fonte externa nao-oficial: {url[:60]}",
                    recommendation="Use apenas import maps oficiais (deno.land, esm.sh). Verifique a URL.",
                    detected_terms=["deno import map hijacking"],
                ))
        return findings

    def detect_eslint_exec(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 11: ESLint plugin execution — only JS/CJS configs, not static JSON"""
        findings = []
        if file_path.suffix.lower() == ".json":
            return findings
        text = content.lower()
        dangerous = [t for t in ["child_process", "exec(", "spawn(", "require(", "process.env"] if t in text]
        if dangerous:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=75.0,
                file_path=file_path, evidence=content[:300],
                category="supply_chain",
                description="Configuracao ESLint contem chamadas perigosas - plugins executam durante lint.",
                recommendation="Audite os plugins ESLint. Plugins maliciosos podem executar codigo no lint.",
                detected_terms=dangerous,
            ))
        return findings

    def detect_prettier_rce(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 12: prettier config RCE"""
        findings = []
        dangerous = [t for t in ["child_process", "exec(", "spawn(", "require("] if t in content.lower()]
        if dangerous:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=75.0,
                file_path=file_path, evidence=content[:300],
                category="supply_chain",
                description="Configuracao Prettier contem chamadas perigosas - pode executar codigo ao formatar.",
                recommendation="Audite a configuracao do Prettier.",
                detected_terms=dangerous,
            ))
        return findings

    def detect_commitlint_poison(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 13: commitlint poisoning"""
        findings = []
        try:
            data = json.loads(content) if file_path.suffix == ".json" else {}
        except Exception:
            data = {}
        extends = data.get("extends", []) if isinstance(data, dict) else []
        for ext in extends if isinstance(extends, list) else []:
            if isinstance(ext, str) and not ext.startswith("@commitlint/"):
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=50.0,
                    file_path=file_path, evidence=f"extends: {ext}",
                    category="supply_chain",
                    description=f"commitlint config extende configuracao externa: {ext}",
                    recommendation="Use apenas plugins oficiais @commitlint/.",
                    detected_terms=["commitlint external"],
                ))
        return findings

    def detect_shrinkwrap(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 15: shrinkwrap malicious tarballs"""
        findings = []
        if re.search(r"https?://[^\s]+(?:\.tgz|\.tar\.gz)", content):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=70.0,
                file_path=file_path, evidence=content[:300],
                category="supply_chain",
                description="npm-shrinkwrap.json contem tarballs de URLs externas - possivel dependency hijacking.",
                recommendation="Verifique os resolved de cada tarball. Prefira registros oficiais.",
                detected_terms=["shrinkwrap tarball"],
            ))
        return findings

    def detect_babel_macro(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 16: babel macro execution"""
        findings = []
        if "macros" in content.lower():
            match = re.search(r'"macros"\s*:\s*\[([^\]]+)\]', content, re.DOTALL)
            if match:
                macros = match.group(1)
                terms = find_suspicious_terms_in_text(macros.lower())
                if terms:
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=75.0,
                        file_path=file_path, evidence=f"macros: {macros[:200]}",
                        category="supply_chain",
                        description="Babel macros contem termos suspeitos - macros executam durante transpilacao.",
                        recommendation="Audite os babel macros. Macros executam codigo durante o build.",
                        detected_terms=terms,
                    ))
        return findings

    def detect_webpack_externals(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 18: webpack externals hijacking"""
        findings = []
        if "externals" in content.lower():
            match = re.search(r'externals\s*[=:]\s*\{', content)
            if match:
                context = content[match.start():match.start() + 400]
                if re.search(r'https?://', context) or re.search(r'process\.env', context):
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=70.0,
                        file_path=file_path, evidence=context[:300],
                        category="supply_chain",
                        description="Webpack externals configurado com URLs ou env vars - possivel hijacking.",
                        recommendation="Audite as externals do webpack. Externals maliciosas podem redirecionar modulos.",
                        detected_terms=["webpack externals"],
                    ))
        return findings

    def detect_vite_rollup_exec(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 19: vite/rollup plugin exec"""
        findings = []
        if "plugins" in content.lower():
            text = content.lower()
            dangerous = [t for t in ["child_process", "exec(", "spawn(", "fs.write", "net.connect"] if t in text]
            if len(dangerous) >= 2:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=80.0,
                    file_path=file_path, evidence=content[:400],
                    category="supply_chain",
                    description=f"Config de bundler contem {len(dangerous)} padroes perigosos - possivel RCE via plugin.",
                    recommendation="Audite plugins do Vite/Rollup. Plugins executam durante dev server e build.",
                    detected_terms=dangerous,
                ))
        return findings

    def detect_vite_exposure(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 20: vite middleware file exposure"""
        findings = []
        if re.search(r"(?:server|middleware|configureServer).*fs", content, re.IGNORECASE):
            if "allow" not in content.lower():
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="MEDIUM", score=50.0,
                    file_path=file_path, evidence=content[:300],
                    category="supply_chain",
                    description="Possivel configuracao Vite que expoe arquivos do sistema via dev server.",
                    recommendation="Configure server.fs.allow para restringir acesso a arquivos no Vite dev server.",
                    detected_terms=["vite exposure"],
                ))
        return findings

    # ── Python Supply Chain ──────────────────────────────────────────────

    def detect_setup_py_rce(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 21: setup.py RCE"""
        findings = []
        text = content.lower()
        terms = find_suspicious_terms_in_text(text)
        has_terms = bool(terms)
        has_code_exec = any(t in text for t in ["os.system(", "subprocess.", "exec(", "eval(", "curl", "wget", "http://", "https://"])
        if has_terms or has_code_exec:
            has_remote = any(t in text for t in ["curl", "wget", "http://", "https://"])
            findings.append(DetectionFinding(
                id=self._next_id(), severity="CRITICAL" if has_remote else "HIGH",
                score=85.0 if has_remote else 70.0,
                file_path=file_path, evidence=content[:400],
                category="supply_chain",
                description="setup.py contem comandos perigosos - executa durante pip install.",
                recommendation="Remova execucao de comandos do setup.py. Use ferramentas de build seguras.",
                detected_terms=terms,
            ))
        return findings

    def detect_pip_conf_poison(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 22: pip.conf poisoning"""
        findings = []
        match = re.search(r"index-url\s*=\s*(https?://[^\s]+)", content)
        if match:
            url = match.group(1)
            if "pypi.org" not in url and "pythonhosted.org" not in url:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=url,
                    category="supply_chain",
                    description=f"pip.conf redireciona index-url para registro personalizado: {url[:60]}",
                    recommendation="Use apenas o PyPI oficial (https://pypi.org/simple/).",
                    detected_terms=["pip.conf poisoning"],
                ))
        return findings

    def detect_extra_index_url(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 23: extra-index-url abuse"""
        findings = []
        for line in content.split("\n"):
            if "--extra-index-url" in line:
                match = re.search(r"--extra-index-url\s+(https?://[^\s]+)", line)
                if match:
                    url = match.group(1)
                    findings.append(DetectionFinding(
                        id=self._next_id(), severity="HIGH", score=70.0,
                        file_path=file_path, evidence=url,
                        category="supply_chain",
                        description=f"requirements.txt contem --extra-index-url apontando para: {url[:60]}",
                        recommendation="Remova --extra-index-url ou verifique se o registro e confiavel.",
                        detected_terms=["extra-index-url"],
                    ))
        return findings

    def detect_tox_shell(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 25: tox.ini shell exec"""
        findings = []
        if "commands" in content.lower() or "passenv" in content.lower():
            text = content.lower()
            terms = find_suspicious_terms_in_text(text)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:300],
                    category="supply_chain",
                    description="tox.ini contem comandos suspeitos - executa durante 'tox'.",
                    recommendation="Audite os comandos no tox.ini.",
                    detected_terms=terms,
                ))
        return findings

    def detect_pytest_plugin(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 26: pytest plugin hijacking"""
        findings = []
        text = content.lower()
        if "conftest.py" in str(file_path).lower() or "pytest" in str(file_path).lower():
            terms = find_suspicious_terms_in_text(text)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:300],
                    category="supply_chain",
                    description="Arquivo de configuracao pytest contem termos suspeitos - plugins executam durante teste.",
                    recommendation="Audite plugins e conftest.py do pytest.",
                    detected_terms=terms,
                ))
        return findings

    def detect_pylint_hook(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 27: pylint init-hook"""
        findings = []
        match = re.search(r'init-hook\s*=\s*(.+)$', content, re.MULTILINE)
        if match:
            hook = match.group(1)
            terms = find_suspicious_terms_in_text(hook.lower())
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=hook[:200],
                    category="supply_chain",
                    description="pylint init-hook contem termos suspeitos - executa codigo ao rodar pylint.",
                    recommendation="Remova codigo perigoso do init-hook do pylint.",
                    detected_terms=terms,
                ))
        return findings

    def detect_flake8_plugin(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 28: flake8 malicious plugins — require exec-class terms, not generic lint terms"""
        findings = []
        text = content.lower()
        exec_terms = [t for t in ["exec(", "eval(", "subprocess", "os.system", "child_process",
                                   "curl", "wget", "base64"] if t in text]
        if exec_terms:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=70.0,
                file_path=file_path, evidence=content[:300],
                category="supply_chain",
                description="Configuracao flake8 contem chamadas de execucao suspeitas - plugins executam durante lint.",
                recommendation="Audite as configs e plugins do flake8.",
                detected_terms=exec_terms,
            ))
        return findings

    def detect_conda_hooks(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 29: conda hooks"""
        findings = []
        text = content.lower()
        terms = find_suspicious_terms_in_text(text)
        if terms and ("activate" in text or "deactivate" in text or "hook" in text):
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=70.0,
                file_path=file_path, evidence=content[:300],
                category="supply_chain",
                description="Script de hook conda contem termos suspeitos - executa ao ativar/desativar env.",
                recommendation="Audite scripts de hook do conda em etc/conda/activate.d e deactivate.d.",
                detected_terms=terms,
            ))
        return findings

    def detect_poetry_build(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 30: poetry build hijacking"""
        findings = []
        text = content.lower()
        if "build" in text or "script" in text:
            terms = find_suspicious_terms_in_text(text)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=75.0,
                    file_path=file_path, evidence=content[:300],
                    category="supply_chain",
                    description="Configuracao Poetry contem termos suspeitos - script de build executa durante 'poetry build'.",
                    recommendation="Audite os scripts de build no pyproject.toml do Poetry.",
                    detected_terms=terms,
                ))
        return findings

    def detect_pipfile_poison(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 31: pipfile source poisoning"""
        findings = []
        match = re.search(r'url\s*=\s*["\'](https?://[^"\']+)["\']', content)
        if match:
            url = match.group(1)
            if "pypi.org" not in url and "pypi.python.org" not in url:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=url,
                    category="supply_chain",
                    description=f"Pipfile source URL nao oficial: {url[:60]}",
                    recommendation="Use apenas fontes PyPI oficiais.",
                    detected_terms=["Pipfile source poisoning"],
                ))
        return findings

    def detect_stdlib_shadow(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 32: stdlib shadowing"""
        findings = []
        STDLIB_MODULES = {
            "os.py", "sys.py", "json.py", "re.py", "math.py",
            "subprocess.py", "socket.py", "http.py", "ssl.py",
            "shutil.py", "pathlib.py", "io.py", "base64.py",
            "pickle.py", "ctypes.py",
        }
        if file_path.name.lower() in STDLIB_MODULES:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=80.0,
                file_path=file_path, evidence=content[:200],
                category="supply_chain",
                description=f"'{file_path.name}' faz shadowing de modulo stdlib - possivel hijacking de import.",
                recommendation=f"Renomeie o arquivo para nao conflitar com o modulo stdlib '{file_path.name}'.",
                detected_terms=["stdlib shadowing"],
            ))
        return findings

    def detect_init_py(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 33: malicious __init__.py"""
        findings = []
        if file_path.name == "__init__.py":
            text = content.lower()
            terms = find_suspicious_terms_in_text(text)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:300],
                    category="supply_chain",
                    description="__init__.py contem termos suspeitos - executa ao importar o pacote.",
                    recommendation="Audite o __init__.py - executa automaticamente ao importar o modulo.",
                    detected_terms=terms,
                ))
        return findings

    def detect_ipython_startup(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 35: IPython startup hooks"""
        findings = []
        text = content.lower()
        terms = find_suspicious_terms_in_text(text)
        if terms:
            findings.append(DetectionFinding(
                id=self._next_id(), severity="HIGH", score=75.0,
                file_path=file_path, evidence=content[:300],
                category="supply_chain",
                description="Script de startup IPython contem termos suspeitos - executa ao iniciar IPython.",
                recommendation="Audite scripts em ~/.ipython/profile_default/startup/.",
                detected_terms=terms,
            ))
        return findings

    def detect_sitecustomize(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 36: sitecustomize persistence"""
        findings = []
        if file_path.name in ("sitecustomize.py", "usercustomize.py"):
            text = content.lower()
            terms = find_suspicious_terms_in_text(text)
            ast_findings = analyze_js_code_with_ast(content)  # wont match, but safe
            has_code_exec = bool(re.search(r"\bos\.system\(|\bsubprocess\.|exec\(|eval\(|__import__", text))
            if has_code_exec or terms:
                findings.append(DetectionFinding(
                    id=self._next_id(),
                    severity="CRITICAL" if has_code_exec else "HIGH",
                    score=90.0 if has_code_exec else 75.0,
                    file_path=file_path, evidence=content[:400],
                    category="supply_chain",
                    description=f"{file_path.name} contem execucao de codigo - executa em todo 'python' no sistema.",
                    recommendation=f"Remova {file_path.name} ou audite seu conteudo - executa no startup de todo interpretador Python.",
                    detected_terms=terms,
                ))
        return findings

    def detect_notebook_abuse(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 34: notebook JS/system abuse"""
        findings = []
        if file_path.suffix == ".ipynb":
            try:
                data = json.loads(content)
            except Exception:
                return findings
            for cell in data.get("cells", []):
                src = "".join(cell.get("source", []))
                lower = src.lower()
                if "!" in src or "%" in src:
                    terms = find_suspicious_terms_in_text(lower)
                    if terms:
                        findings.append(DetectionFinding(
                            id=self._next_id(), severity="HIGH", score=70.0,
                            file_path=file_path, evidence=src[:300],
                            category="supply_chain",
                            description="Notebook Jupyter contem comandos shell/system - executa ao executar celula.",
                            recommendation="Audite as celulas do notebook com comandos shell.",
                            detected_terms=terms,
                        ))
        return findings

    def detect_sphinx_conf(self, file_path: Path, content: str) -> list[DetectionFinding]:
        """Vector 40: sphinx conf.py execution"""
        findings = []
        if file_path.name == "conf.py" and "sphinx" in str(file_path).lower():
            text = content.lower()
            terms = find_suspicious_terms_in_text(text)
            if terms:
                findings.append(DetectionFinding(
                    id=self._next_id(), severity="HIGH", score=70.0,
                    file_path=file_path, evidence=content[:300],
                    category="supply_chain",
                    description="Sphinx conf.py contem termos suspeitos - executa durante 'make html' ou 'sphinx-build'.",
                    recommendation="Audite conf.py do Sphinx - e executado como codigo Python no build.",
                    detected_terms=terms,
                ))
        return findings

    # ── Orquestrador ─────────────────────────────────────────────────────

    def scan_file(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        name = file_path.name.lower()
        handlers = {
            ".npmrc": self.detect_npmrc_hijacking,
            ".yarnrc": self.detect_npmrc_hijacking,
            ".yarnrc.yml": self.detect_npmrc_hijacking,
            "package.json": self._scan_package_json,
            ".nvmrc": self.detect_nvmrc_injection,
            "npm-shrinkwrap.json": self.detect_shrinkwrap,
            ".eslintrc.js": self.detect_eslint_exec,
            ".eslintrc.json": self.detect_eslint_exec,
            ".prettierrc.js": self.detect_prettier_rce,
            "commitlint.config.js": self.detect_commitlint_poison,
            "babel.config.js": self.detect_babel_macro,
            "webpack.config.js": self.detect_webpack_externals,
            "vite.config.js": self.detect_vite_rollup_exec,
            "vite.config.ts": self.detect_vite_rollup_exec,
            "bunfig.toml": self.detect_bunfig_abuse,
            "setup.py": self.detect_setup_py_rce,
            "pip.conf": self.detect_pip_conf_poison,
            "tox.ini": self.detect_tox_shell,
            "pyproject.toml": self._scan_pyproject_toml,
            "Pipfile": self.detect_pipfile_poison,
            "sitecustomize.py": self.detect_sitecustomize,
            "usercustomize.py": self.detect_sitecustomize,
            "__init__.py": self.detect_init_py,
            "conf.py": self.detect_sphinx_conf,
        }
        handler = handlers.get(name)
        if handler:
            findings.extend(handler(file_path, content))

        if file_path.suffix == ".ipynb":
            findings.extend(self.detect_notebook_abuse(file_path, content))
        if file_path.name.startswith("requirements") and file_path.suffix == ".txt":
            findings.extend(self.detect_extra_index_url(file_path, content))
        if name.endswith(".cfg") and "flake8" in content.lower():
            findings.extend(self.detect_flake8_plugin(file_path, content))
        if "pytest" in content.lower() and file_path.suffix in (".ini", ".cfg", ".toml"):
            findings.extend(self.detect_pytest_plugin(file_path, content))
        if name.startswith(".pylintrc") or name == "pylintrc":
            findings.extend(self.detect_pylint_hook(file_path, content))
        if "conda" in str(file_path) and file_path.suffix in (".sh", ".py"):
            findings.extend(self.detect_conda_hooks(file_path, content))

        return findings

    def _scan_package_json(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        findings.extend(self.detect_npm_lifecycle_hooks(file_path, content))
        findings.extend(self.detect_typosquatting(file_path, content))
        findings.extend(self.detect_bundled_deps(file_path, content))
        findings.extend(self.detect_malicious_bin(file_path, content))
        findings.extend(self.detect_bin_hijacking(file_path, content))
        findings.extend(self.detect_node_options(file_path, content))
        return findings

    def _scan_pyproject_toml(self, file_path: Path, content: str) -> list[DetectionFinding]:
        findings = []
        findings.extend(self.detect_poetry_build(file_path, content))
        findings.extend(self.detect_tox_shell(file_path, content))
        findings.extend(self.detect_pytest_plugin(file_path, content))
        return findings
