#!/usr/bin/env bash
# Build macOS .app bundle with PyInstaller
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="VSCode Security Scanner"
BUNDLE_ID="com.vscodescanner.app"
ICON_PATH=""  # Set to e.g. "$PROJECT_DIR/assets/icon.icns" for a custom icon

cd "$PROJECT_DIR"

uv sync

# Ensure PyInstaller is available
uv run python -c "import PyInstaller" 2>/dev/null || uv add --dev pyinstaller

PYI_ARGS=(
    --onedir
    --windowed
    --name "$APP_NAME"
    --osx-bundle-identifier "$BUNDLE_ID"
    --add-data "rules.toml:."
    --add-data "gui:gui"
    --hidden-import "tomli"
    --hidden-import "yaml"
    --hidden-import "esprima"
    --hidden-import "reportlab"
    --hidden-import "structlog"
    --collect-data "customtkinter"
    --collect-submodules "gui"
    --collect-submodules "security_scanner"
    --additional-hooks-dir "hooks"
    --noconfirm
    --clean
)

if [ -n "$ICON_PATH" ] && [ -f "$ICON_PATH" ]; then
    PYI_ARGS+=(--icon "$ICON_PATH")
fi

uv run pyinstaller "${PYI_ARGS[@]}" main.py

APP_BUNDLE="dist/$APP_NAME.app"

# PyInstaller already ad-hoc signs the binary and bundle on macOS.
# The main blocker is the quarantine attribute set by Gatekeeper on downloaded apps.
# Since we built locally, there is no quarantine — but removing it explicitly
# avoids issues if the .app is ever copied via AirDrop, zip, etc.
xattr -cr "$APP_BUNDLE" 2>/dev/null || true

echo ""
echo "[OK] .app built: $APP_BUNDLE"
echo ""
echo "Para abrir no macOS Tahoe:"
echo "  1. Clique com o botao direito -> Abrir (nao duplo clique)"
echo "  2. Va em Ajustes -> Privacidade e Seguranca -> \"Permitir mesmo assim\""
echo ""
echo "Para verificar a assinatura:"
echo "  codesign -dvvv \"$APP_BUNDLE\""
