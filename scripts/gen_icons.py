# -*- coding: utf-8 -*-
"""生成托盘三态图标：green/red/yellow 实心圆，64x64 PNG，输出到 assets/。"""
from pathlib import Path

from PIL import Image, ImageDraw

SIZE = 64
COLORS = {
    "green": (40, 200, 80, 255),
    "red": (232, 64, 52, 255),
    "yellow": (245, 197, 24, 255),
}
OUT = Path(__file__).resolve().parent.parent / "assets"


def gen(color: str, rgba) -> Path:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((2, 2, SIZE - 2, SIZE - 2), fill=rgba)
    path = OUT / f"{color}.png"
    img.save(path)
    return path


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, rgba in COLORS.items():
        print(gen(name, rgba))


if __name__ == "__main__":
    main()
