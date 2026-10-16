# -*- coding: utf-8 -*-
"""资源路径与图标加载帮助。

兼容开发运行与 PyInstaller 打包（sys._MEIPASS）两种场景。
"""
import sys
from pathlib import Path


def assets_path(*parts: str) -> Path:
    """返回 assets/ 内资源的绝对路径。

    PyInstaller 打包（--add-data "assets;assets"）时资源解压到 sys._MEIPASS。
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = Path(sys._MEIPASS) / "assets"
    else:
        base = Path(__file__).resolve().parent.parent / "assets"
    return base.joinpath(*parts)


def icon_file(color: str) -> Path:
    """三态图标路径：color ∈ {green, red, yellow}。"""
    return assets_path(f"{color}.png")
