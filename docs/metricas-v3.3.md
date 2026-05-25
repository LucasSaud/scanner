# Scanner v3.3 — Relatório de Métricas Finais

## Visão Geral

| Métrica | v3.0 | v3.1 | v3.2 | **v3.3** |
|---------|------|------|------|----------|
| Vetores de ataque | 11 | 5 | 6 | **+16 = 38** |
| Funções analisadoras | 11 | 5 | 6 | **+11 = 33** |
| Engine features | 5 | 2 | 2 | **+7 = 16** |
| Linhas de código (engine) | ~450 | ~200 | ~250 | **+450 = ~2100** |
| Deps externas | 3 | 0 | 0 | **0 (stdlib)** |
| Versão do scanner | — | — | 3.0.0 | **3.3.0** |

---

## Tabela Completa de Vetores (38)

### v3.0 — Vetores Base (11)

| # | Vetor | Arquivo(s) Alvo | Severidade | Função |
|---|-------|-----------------|------------|--------|
| 1 | VSCode tasks.json | `.vscode/tasks.json` | CRITICAL → MEDIUM | `analyze_vscode_tasks_json` |
| 2 | VSCode settings.json | `.vscode/settings.json` | HIGH | `analyze_vscode_settings_json` |
| 3 | VSCode extensions.json | `.vscode/extensions.json` | MEDIUM | `analyze_vscode_extensions_json` |
| 4 | VSCode launch.json | `.vscode/launch.json` | HIGH | `analyze_vscode_launch_json` |
| 5 | npm lifecycle scripts | `package.json` | CRITICAL → MEDIUM | `analyze_npm_package_json_lifecycle_scripts` |
| 6 | npmrc / yarnrc | `.npmrc`, `.yarnrc.yml` | HIGH | `analyze_npmrc_yarnrc` |
| 7 | devcontainer | `.devcontainer/devcontainer.json` | CRITICAL | `analyze_devcontainer_auto_execution_commands` |
| 8 | Git hooks | `.git/hooks/*` | HIGH → MEDIUM | `analyze_git_hook_script` |
| 9 | Python build files | `setup.py`, `setup.cfg`, `pyproject.toml` | MEDIUM | `analyze_python_build_file` |
| 10 | Symlink escape | Qualquer symlink | HIGH | `check_symlinks_outside_project` |
| 11 | Global ~/.vscode/ | `~/.vscode/*` | HIGH | `scan_global_vscode_directory` |

### v3.1 — Supply Chain 1 (5)

| # | Vetor | Arquivo(s) Alvo | Severidade | Função |
|---|-------|-----------------|------------|--------|
| 12 | Dockerfile | `Dockerfile*` | CRITICAL → MEDIUM | `analyze_dockerfile` |
| 13 | GitHub Actions | `.github/workflows/*.yml` | HIGH | `analyze_github_actions_workflow` |
| 14 | Makefile | `Makefile`, `makefile` | HIGH → MEDIUM | `analyze_makefile` |
| 15 | Cargo build.rs | `build.rs`, `Cargo.toml` | HIGH → MEDIUM | `analyze_cargo_build_rs` |
| 16 | Pre-commit config | `.pre-commit-config.yaml` | HIGH → MEDIUM | `analyze_pre_commit_config` |

### v3.2 — Supply Chain 2 (6)

| # | Vetor | Arquivo(s) Alvo | Severidade | Função |
|---|-------|-----------------|------------|--------|
| 17 | Docker Compose | `docker-compose*.yml` | HIGH → MEDIUM | `analyze_docker_compose` |
| 18 | VSCode keybindings | `.vscode/keybindings.json` | HIGH → MEDIUM | `analyze_vscode_keybindings` |
| 19 | Pip config poisoning | `pip.conf`, `Pipfile`, `requirements*.txt` | HIGH → MEDIUM | `analyze_pip_config` |
| 20 | Justfile / Taskfile | `Justfile`, `justfile`, `Taskfile.yml` | HIGH | `analyze_justfile` |
| 21 | Gemfile / .gemspec | `Gemfile`, `*.gemspec` | HIGH → MEDIUM | `analyze_gemfile` |
| 22 | Bootstrap scripts | `configure`, `install.sh`, `bootstrap.sh` | HIGH → MEDIUM | `analyze_bootstrap_scripts` |

### v3.3 — Novos Vetores (16)

| # | Vetor | Arquivo(s) Alvo | Severidade | Função |
|---|-------|-----------------|------------|--------|
| 23 | Git sshCommand | `.git/config` | HIGH | `analyze_git_config` |
| 24 | Git submodules | `.gitmodules` | HIGH → MEDIUM | `analyze_git_submodules` |
| 25 | Workspace settings | `*.code-workspace` | HIGH | `analyze_vscode_workspace` |
| 26 | VSCode snippets | `.vscode/*.code-snippets` | HIGH → MEDIUM | `analyze_vscode_snippets` |
| 27 | Docker cap_add | `docker-compose*.yml` | HIGH | `_check_cap_add` (extensão) |
| 28 | VSIX packages | `*.vsix` | MEDIUM | `analyze_vsix_packages` |
| 29 | Composer scripts | `composer.json` | HIGH | `analyze_composer_json` |
| 30 | Husky hooks | `.husky/*` | HIGH → MEDIUM | `analyze_husky_hooks` |
| 31 | Monorepo tasks | `lerna.json`, `nx.json`, `turbo.json` | HIGH | `analyze_monorepo_tasks` |
| 32 | pnpmfile | `pnpmfile.js` | HIGH | `analyze_pnpmfile` |
| 33 | Cargo registry | `.cargo/config.toml` | HIGH → MEDIUM | `analyze_cargo_registry` |
| 34 | Go mod replace | `go.mod` | HIGH → MEDIUM | `analyze_go_mod` |
| 35 | Gradle init scripts | `init.gradle*` | HIGH | `analyze_gradle_init` |
| 36 | Maven extensions | `pom.xml` | HIGH → MEDIUM | `analyze_maven_extensions` |
| 37 | GH Actions workflow_call | `.github/workflows/*.yml` | HIGH | `_extended_gh_actions_check` (extensão) |
| 38 | .env secrets | `.env*` | HIGH → MEDIUM | `analyze_dotenv_secrets` |

---

## Engine Features (16)

### 1. Obfuscation — Normalize Text
Decodifica hex encoding (`\x68\x74\x74\x70`), remove backslash-escaping (`c\url`), remove quotes entre caracteres (`w'g'et`), e remove marcadores de subshell (`$(...)`, `` `...` ``).

### 2. Recursive Normalize (v3.3)
Aplica `normalize_text` + `normalize_homoglyphs` em loop até estabilizar (máx. 5 iterações). Captura ofuscação aninhada como `c\ur\x6c` → `curl`.

### 3. Unicode Homoglyph Normalization (v3.3)
Mapeia ~150 caracteres Unicode (Cyrillic, Greek, Fullwidth Latin, Latin extended) para seus equivalentes ASCII. Ex: `сurl` (Cyrillic с) → `curl`. Aplicado durante `normalize_text_recursive`.

### 4. Base64 Pipeline Detection
Detecta `base64 -d | bash`, `echo <base64> | base64 -d | sh`, e `echo <long-base64> | bash`.

### 5. JS Join Obfuscation Detect
Detecta `['b','a','s','h'].join('')` e `String.fromCharCode()`.

### 6. AST Parsing (Optional)
Com `esprima` instalado, analisa código JavaScript para detectar `child_process.exec`, `.spawn()`, `eval()`.

### 7. Shannon Entropy (Global)
Calcula entropia de Shannon de todo o conteúdo; threshold configurável via `rules.toml` (default 4.5 bits/char).

### 8. Per-Line Entropy (v3.3)
Calcula entropia por linha; flag se > 6.0 bits/char com comprimento mínimo de 20 caracteres. Detecta base64/AES em linhas individuais.

### 9. JSONC Parser
Parser de JSON com comentários (// e /* */) sem dependência externa. Usado em todos os arquivos `.json` do VSCode e devcontainer.

### 10. Directory Exclusion
31 nomes de diretório excluídos do scan: `.venv`, `venv`, `env`, `node_modules`, `site-packages`, `__pycache__`, `.tox`, `.eggs`, `dist`, `build`, `.mypy_cache`, `.pytest_cache`, `.git` (v3.3). Aplicado em TODAS as chamadas `glob()` e `rglob()`.

### 11. Excluded Dir Tracking
Coleta e expõe quais tipos de diretório foram excluídos para exibição na GUI (status bar).

### 12. Richer JSON Report (v3.3)
`export_findings_report_as_json()` agora inclui por finding: `line_number`, `suggestion`, `risk_score` (0–10). Versão do report atualizada para 3.3.0.

### 13. Skeleton Loaders (GUI)
`SkeletonCard` — cards com gradiente animado (pulsing) durante o scan, substituídos por `FindingCard` ao concluir.

### 14. CLI Mode
`cli.py scan --path . --json report.json --no-global` — headless, CI/CD ready, sem dependência de Tkinter.

### 15. Externalized Rules
Todas as regras em `rules.toml`: `execution_terms`, `url_patterns`, `auto_execution_hooks`, `dangerous_settings_keys`, `entropy_threshold`. Atualizáveis sem modificar código.

### 16. Build Scripts
`scripts/build_app.sh` (PyInstaller → macOS .app bundle) e `scripts/build_cli.sh` (PyInstaller → single binary).

---

## Dependências

| Biblioteca | Versão | Origem | Obrigatória? |
|-----------|--------|--------|-------------|
| `customtkinter` | ≥5.2.2 | PyPI | Sim (GUI) |
| `tomli` | ≥2.0.0 | PyPI | Sim (rules.toml) |
| `pyyaml` | — | PyPI | Sim (YAML parse) |
| `esprima` | — | PyPI | Opcional (AST) |
| `configparser` | stdlib | Python | Stdlib |
| `xml.etree.ElementTree` | stdlib | Python | Stdlib |
| `unicodedata` | stdlib | Python | Stdlib |
| `json`, `re`, `math` | stdlib | Python | Stdlib |
