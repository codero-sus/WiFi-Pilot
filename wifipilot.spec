# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for wifipilot. Builds a single-file Linux executable that
# embeds the web UI, data files, and bundled docs. Run via:
#
#   pyinstaller --clean wifipilot.spec
#
# Output: dist/wifipilot

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hidden = []
# Eager-import the attack registry modules so none is missed by the
# static-analysis tree walker (the registry uses __init_subclass__ to
# self-register, so attackers are only reachable via __init__.py).
hidden += collect_submodules("wifipilot.attacks")
# Advisor backends and web stack may also be imported lazily.
hidden += collect_submodules("wifipilot.web")

a = Analysis(
    ["wifipilot/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("wifipilot/web/static", "wifipilot/web/static"),
        ("wifipilot/data",        "wifipilot/data"),
        ("docs",                  "docs"),
        ("LICENSE",               "."),
        ("NOTICE",                "."),
        ("THIRD-PARTY.md",        "."),
    ],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Not used at runtime; trim the bundle.
        "tkinter", "turtle", "pydoc", "unittest", "distutils",
        "email.mime", "xmlrpc", "pytest", "pip",
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="wifipilot",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
