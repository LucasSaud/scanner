# AGENTS.md — VSCode Security Scanner

## Overview

Modular Python project that scans VSCode project directories and global `~/.vscode/` for suspicious tasks.json, settings.json, extensions.json, git hooks, npm lifecycle scripts, registry config, Python build files, and symlink escapes.

## Entrypoints

- **CLI**: `uv run python cli.py scan --path . [--json report.json] [--no-global]`
- **GUI**: `uv run python main.py` (default) or `uv run python main.py --gui`

## Dependencies

Managed via `uv`:
- `customtkinter>=5.2.2` — GUI framework
- `tomli>=2.0.0` — TOML parser for rules.toml
- `esprima>=1.1.0` — optional AST parsing for JS (install with `uv sync --extra ast`)

## Project structure

```
scanner/
├── pyproject.toml        # Declares deps, uv lock generates uv.lock
├── uv.lock               # Locked dependency versions
├── rules.toml            # Externalized detection rules (no hardcoded terms)
├── models.py             # DetectionFinding dataclass, SEVERITY constants
├── scanner_engine.py     # Detection engine, JSONC parser, obfuscation resistance
├── cli.py                # Headless CLI mode for CI/CD (no Tkinter)
├── main.py               # Entry point: --gui (default) or --cli
├── gui/
│   ├── __init__.py
│   ├── app.py            # VSCodeSecurityScannerApp (customtkinter QMainWindow)
│   ├── widgets.py        # FindingCard (clickable result card) + SkeletonCard (loader)
│   └── theme.py          # Font, color constants
└── scripts/
    ├── build_app.sh      # PyInstaller → macOS .app bundle
    └── build_cli.sh      # PyInstaller → single CLI binary
```

## Key features

- **Obfuscation resistance**: normalizes `c\url`, `w'g'et`, `$(...)`, backtick expansion before term matching
- **Shannon entropy**: flags scripts with entropy > 4.5 bits/char (potential base64/AES)
- **JS join detection**: detects `['b','a','s','h'].join('')` patterns
- **AST parsing (optional)**: if `esprima` installed, parses JS scripts for dangerous calls
- **Skeleton loaders**: animated pulsing placeholders during scan
- **Rules externalized** to `rules.toml` — update signatures without code changes

## Important quirks

- `scan_project_directory()` walks `**` globs — can be slow on large trees
- Global VSCode scan (`~/.vscode/`) skips `extensions/` subdirectory but still walks the rest
- JSONC parsing is custom, not a library
