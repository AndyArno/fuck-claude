# -*- mode: python ; coding: utf-8 -*-
"""Claude Guard PyInstaller spec。

构建：.venv/Scripts/pyinstaller.exe claude-guard.spec
产物：dist/ClaudeGuard.exe（单文件，UAC 自提升）

注意：config.json 不打包进 exe —— 需求 P-3 要求配置外置、用户可编辑，
打包后由入口从 exe 同目录加载；随包分发时把 config.json 复制到 exe 旁边。
"""
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = [
    # pystray 的 Windows 后端与依赖
    *collect_submodules("pystray._win32"),
    "pystray._util.win32",
    # win11toast 通知后端（动态导入）
    *collect_submodules("win11toast"),
    "psutil._psutil_windows",
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("assets/green.png", "assets"),
           ("assets/red.png", "assets"),
           ("assets/yellow.png", "assets")],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "IPython", "jedi", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ClaudeGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon="assets/claude-guard.ico",
)
