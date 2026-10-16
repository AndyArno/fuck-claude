# -*- coding: utf-8 -*-
"""Claude Guard 开发态入口。

用法：
  python scripts/run_guardian.py           # 启动托盘 + Guardian 主循环
  python scripts/run_guardian.py --check   # 自检：跑一轮快慢检查并打印结果后退出
                                           # （不启动托盘、不修改防火墙）

Ctrl+C 干净退出：守护线程随主线程结束；规则保持当前实际状态（fail-closed）。
guardian.py 本身不含入口副作用，可被 exe 打包入口（PyInstaller）直接复用。
"""
from __future__ import annotations

import signal
import sys
import threading
from pathlib import Path

# 保证以脚本方式（python scripts/run_guardian.py）运行时能找到项目根的包
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.config import ConfigError, load as load_config  # noqa: E402
from guardian import Guardian, selfcheck, setup_logging  # noqa: E402

CONFIG_PATH = _ROOT / "config.json"


def main(argv: list[str]) -> int:
    if "--check" in argv:
        try:
            config = load_config(CONFIG_PATH)
        except ConfigError as exc:
            print(f"配置错误：{exc}")
            return 2
        return selfcheck(config)

    try:
        config = load_config(CONFIG_PATH)
    except ConfigError as exc:
        print(f"配置错误：{exc}")
        return 2
    log = setup_logging(config)

    log.info("===== Claude Guard 启动（开发态入口）=====")
    try:
        from tray import Tray
    except Exception as exc:
        log.error("托盘初始化失败（无显示环境或缺依赖）：%s", exc)
        return 1

    tray = Tray()
    guardian = Guardian(config, CONFIG_PATH, tray=tray, logger=log)

    stop_done = threading.Event()

    def _signal_stop(signum, frame):  # noqa: ANN001
        log.info("收到信号 %s，退出（规则保持当前实际状态，fail-closed）", signum)
        stop_done.set()
        guardian.stop()

    signal.signal(signal.SIGINT, _signal_stop)
    signal.signal(signal.SIGTERM, _signal_stop)

    tray.start()
    guardian.start()

    try:
        while not stop_done.wait(timeout=1.0):
            if not guardian._thread.is_alive():  # noqa: SLF001 - 入口巡检
                log.error("Guardian 主循环线程意外退出，停止进程")
                break
    except KeyboardInterrupt:
        log.info("Ctrl+C 退出（规则保持当前实际状态，fail-closed）")
        guardian.stop()
    finally:
        tray.stop()
        log.info("===== Claude Guard 已退出 =====")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
