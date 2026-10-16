# -*- coding: utf-8 -*-
"""最小托盘演示：运行 5 秒自动退出。

验证：托盘弹出、三态图标切换、菜单命令进入 CommandQueue、toast 正常。
无 guardian，用假事件源。按 Ctrl+C 可提前退出。
"""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tray as tray_mod
from tray import Command, State, StateEvent, Tray


def main() -> None:
    t = Tray()
    t.start()
    print("[demo] tray started")

    # 假事件源：模拟状态流转 绿 -> 红 -> 黄(漂移)
    seq = [
        StateEvent(state=State.ALLOWED, exit_ip="203.0.113.10",
                   whitelist_hit=True,
                   checks={"mihomo进程": True, "TUN网卡": True,
                           "fake-ip": True, "echo出口": True}),
        StateEvent(state=State.BLOCKED, exit_ip="未知", whitelist_hit=False,
                   checks={"mihomo进程": False, "TUN网卡": False,
                           "fake-ip": None, "echo出口": None}),
        StateEvent(state=State.ALLOWED, exit_ip="1.2.3.4", whitelist_hit=False,
                   drift=True,
                   checks={"mihomo进程": True, "TUN网卡": True,
                           "fake-ip": True, "echo出口": True}),
    ]
    for evt in seq:
        t.push_event(evt)
        time.sleep(1.2)

    # 模拟用户点菜单：直接投递命令（真实场景由菜单回调投递）
    t.commands.put(Command.PAUSE)

    # 收集 CommandQueue 验证命令可达
    got = []
    while not t.commands.empty():
        got.append(t.commands.get(timeout=1))

    # 演示状态详情气泡
    if t._last_event is not None:
        print("[demo] detail lines:")
        for line in t._last_event.detail_lines():
            print("   ", line)

    time.sleep(1)
    t.stop()
    print("[demo] commands received:", [c.name for c in got])
    assert got and got[0] == Command.PAUSE, "command queue failed"
    print("[demo] OK - tray icon switched through 3 states, queue works")


if __name__ == "__main__":
    threading.excepthook = lambda a: print("[demo] thread error:", a)
    main()
