# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.hooks import collect_submodules

datas = [('rules.toml', '.'), ('gui', 'gui')]
hiddenimports = ['tomli', 'yaml', 'esprima', 'reportlab', 'structlog']
datas += collect_data_files('customtkinter')
hiddenimports += collect_submodules('gui')
hiddenimports += collect_submodules('security_scanner')


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=['hooks'],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='VSCode Security Scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='VSCode Security Scanner',
)
app = BUNDLE(
    coll,
    name='VSCode Security Scanner.app',
    icon=None,
    bundle_identifier='com.vscodescanner.app',
)
