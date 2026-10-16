# -*- coding: utf-8 -*-
"""Claude Guard 打包入口（PyInstaller）。

- frozen（exe）时 config.json 从 exe 同目录加载（用户可编辑，不打包进 exe）；
  脚本运行时与 scripts/run_guardian.py 行为一致。
- 无 console（--windowed）：--check 模式下用 MessageBox 输出结果，
  正常模式静默启动托盘 + Guardian。
"""
from __future__ import annotations

import sys
from pathlib import Path

# 打包后 guardian/scripts 不在包结构顶层：把项目根加进模块搜索路径
if not getattr(sys, "frozen", False):
    _ROOT = Path(__file__).resolve().parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from scripts.run_guardian import main  # noqa: E402
from winplat.winmsg import message_box as _message_box  # noqa: E402


def _frozen_check() -> int:
    """exe 下的 --check：抓 stdout 跑自检，结果用 MessageBox 展示。"""
    import io
    from contextlib import redirect_stdout

    from core.config import ConfigError, load as load_config
    from guardian import selfcheck
    from winplat.assets import icon_file

    exe_dir = Path(sys.executable).resolve().parent
    config_path = exe_dir / "config.json"

    buf = io.StringIO()
    code = 0
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _message_box("Claude Guard 自检失败",
                     f"配置错误：{exc}\n\n路径: {config_path}", error=True)
        return 2
    with redirect_stdout(buf):
        code = selfcheck(config)
    # 图标资源自检：三张图标必须能从 _MEIPASS/assets 加载（技术细节，附在末尾）
    icons_ok = True
    for color in ("green", "red", "yellow"):
        p = icon_file(color)
        if not p.is_file():
            icons_ok = False
            print(f"图标资源缺失: {p}")
    if not icons_ok:
        code = 3
        print("图标资源自检: 失败")
    _message_box("Claude Guard 自检结果", buf.getvalue(), error=code != 0)
    return code


if __name__ == "__main__":
    if "--check" in sys.argv[1:] and getattr(sys, "frozen", False):
        sys.exit(_frozen_check())
    sys.exit(main(sys.argv[1:]))
