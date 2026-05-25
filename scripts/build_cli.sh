#!/usr/bin/env bash
# Build CLI-only binary with PyInstaller + ad-hoc codesign
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="vscode-scanner"

cd "$PROJECT_DIR"

uv sync

# Ensure PyInstaller is available
uv run python -c "import PyInstaller" 2>/dev/null || uv add --dev pyinstaller

uv run pyinstaller \
    --onefile \
    --name "$APP_NAME" \
    --add-data "rules.toml:." \
    --hidden-import "tomli" \
    --hidden-import "yaml" \
    --hidden-import "esprima" \
    --hidden-import "reportlab" \
    --hidden-import "structlog" \
    --collect-submodules "security_scanner" \
    --clean \
    cli.py

BINARY="dist/$APP_NAME"

# Codesign the binary
if [ -x "$BINARY" ]; then
    echo ""
    echo "[SIGN] Ad-hoc signing binary..."
    codesign --force --sign - --options runtime "$BINARY"
    echo "[CLEAN] Removing quarantine xattr..."
    xattr -cr "$BINARY" 2>/dev/null || true
fi

echo ""
echo "[OK] Binary built and signed: $BINARY"
echo "    Run with: $BINARY scan --path ."
