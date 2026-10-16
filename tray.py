# -*- coding: utf-8 -*-
"""托盘表示层（pystray）。

线程模型（架构文档 §2.3/§4）：
- pystray Icon 在独立线程运行消息循环（icon.run_detached）。
- 与 guardian 之间只通过两个队列通信，禁止跨线程直接调用：
  * EventQueue   guardian -> tray：状态事件（StateEvent）
  * CommandQueue tray -> guardian：菜单命令（Command）
- 托盘线程永不执行业务逻辑：菜单回调只投递命令 + 更新图标/tooltip。
"""
import enum
import os
import queue
import threading
from dataclasses import dataclass, field

import pystray
from PIL import Image

from winplat.assets import icon_file
from winplat.winmsg import message_box_async
from core.messages import (
    DRIFT_HINT,
    Status,
    TECH_SEPARATOR,
    reason_line,
    status_line,
    tooltip as tooltip_text,
)


class State(enum.Enum):
    BLOCKED = "阻断"
    ALLOWED = "放行"
    # DRIFT_ALARM 为正交标志位，附着于任意状态


class Command(enum.Enum):
    SHOW_DETAILS = "show_details"
    OVERRIDE_30MIN = "override_30min"
    PAUSE = "pause"
    RESUME = "resume"
    EDIT_WHITELIST = "edit_whitelist"
    EXIT = "exit"  # T-6：退出前恢复阻断（Enabled）
    QUIT = "quit"  # 仅调试：保持当前规则状态退出


@dataclass
class StateEvent:
    """guardian -> tray 的状态摘要事件。

    checks 仅承载各检查项是否通过（None=未探测），不携带文案；
    用户可见文案统一由 core.messages 生成。
    """

    state: State
    exit_ip: str = "未知"
    whitelist_hit: bool = False
    # 检查⑤ DNS 出口探针看到的解析出口 IP（None=未探测/干净）
    dns_leak_ip: str | None = None
    # 检查结果：名称 -> bool（True=通过 False=失败）
    checks: dict = field(default_factory=dict)
    paused: bool = False
    drift: bool = False
    override_active: bool = False
    # 启动确认期：拦截中但检查已全过（等待连续确认），文案显示"确认中"
    confirming: bool = False

    def _status(self) -> Status:
        c = self.checks
        dns_leak = self.dns_leak_ip if c.get("DNS出口干净") is False else None
        return Status(
            blocking=self.state is State.BLOCKED,
            paused=self.paused,
            override_min_left=(-1 if self.override_active else None),
            confirming=self.confirming,
            proxy_ok=c.get("mihomo进程"),
            tunnel_ok=c.get("TUN网卡"),
            dns_ok=c.get("fake-ip"),
            dns_leak_ip=dns_leak,
            probe_ok=c.get("echo出口"),
            exit_ip=self.exit_ip,
            in_whitelist=self.whitelist_hit,
        )

    def icon_color(self) -> str:
        if self.drift:
            return "yellow"
        if self.paused:
            return "yellow"
        return {
            State.BLOCKED: "red",
            State.ALLOWED: "green",
        }[self.state]

    def tooltip(self) -> str:
        return tooltip_text(self._status())

    def detail_lines(self) -> list:
        """状态详情：第一行防火墙状态，拦截态第二行大白话原因，分隔线后技术细节。"""
        s = self._status()
        lines = [status_line(s)]
        if s.blocking and not self.paused:
            lines.append(reason_line(s))
        if self.drift:
            lines.append(DRIFT_HINT)
        lines.append("")
        lines.append(TECH_SEPARATOR)
        lines.append(f"状态: {self.state.value}"
                     + ("（已暂停）" if self.paused else "")
                     + ("（临时放行中）" if self.override_active else ""))
        lines.append(f"出口 IP: {self.exit_ip}")
        lines.append(f"白名单命中: {'是' if self.whitelist_hit else '否'}")
        if self.dns_leak_ip:
            lines.append(f"DNS 解析出口: {self.dns_leak_ip}")
        for name, result in self.checks.items():
            shown = {True: "通过", False: "未通过"}.get(result, "未探测")
            lines.append(f"{name}: {shown}")
        return lines


class Tray:
    """pystray 托盘。接口：start / stop / push_event / CommandQueue。"""

    def __init__(self) -> None:
        self.events: "queue.Queue[StateEvent]" = queue.Queue()
        self.commands: "queue.Queue[Command]" = queue.Queue()
        self._icons = {c: Image.open(icon_file(c)) for c in ("green", "red", "yellow")}
        self._icon: pystray.Icon = None  # type: ignore[assignment]
        self._stop_done = threading.Event()
        self._last_event: StateEvent | None = None

    # ---- guardian 侧接口 -------------------------------------------------

    def start(self) -> None:
        self._icon = pystray.Icon(
            "ClaudeGuard",
            icon=self._icons["yellow"],
            title="Claude Guard 启动中",
            menu=self._build_menu(),
        )
        self._icon.run_detached()
        # 消费队列，把事件映射到图标/tooltip（托盘线程内执行，均为 UI 更新）
        t = threading.Thread(target=self._event_loop, name="tray-events", daemon=True)
        t.start()

    def stop(self) -> None:
        self.events.put(None)  # 停事件循环
        self._stop_done.wait(timeout=3)
        try:
            self._icon.stop()
        except Exception:
            pass

    def push_event(self, event: StateEvent) -> None:
        """guardian 主循环线程调用；线程安全（queue）。"""
        self.events.put(event)

    # ---- 托盘线程内部 ----------------------------------------------------

    def _event_loop(self) -> None:
        while True:
            evt = self.events.get()
            if evt is None:
                self._stop_done.set()
                return
            try:
                self._apply(evt)
            except Exception:
                pass  # UI 更新失败不影响守护

    def _apply(self, evt: StateEvent) -> None:
        color = evt.icon_color()
        img = self._icons[color]
        if self._icon.icon is not img:
            self._icon.icon = img
        self._icon.title = evt.tooltip()
        self._last_event = evt

    def _menu_cb(self, cmd: Command):
        def callback(icon, item):
            self.commands.put(cmd)  # 只投递，不执行业务

        return callback

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(
                "状态详情", self._show_details, default=True
            ),
            pystray.MenuItem(
                "临时放行 30 分钟", self._menu_cb(Command.OVERRIDE_30MIN)
            ),
            pystray.MenuItem("暂停守护", self._menu_cb(Command.PAUSE)),
            pystray.MenuItem("恢复守护", self._menu_cb(Command.RESUME)),
            pystray.MenuItem("编辑白名单", self._menu_cb(Command.EDIT_WHITELIST)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出（恢复阻断）", self._menu_cb(Command.EXIT)),
        )

    def _show_details(self, icon, item) -> None:
        """状态详情：投递命令，同时弹出真窗口展示最近一次事件的完整详情。

        MessageBoxW 在独立 daemon 线程弹出（线程内模态），托盘消息泵与
        guardian 主循环均不受阻塞；窗口由用户点"确定"关闭。"""
        self.commands.put(Command.SHOW_DETAILS)
        evt = self._last_event
        if evt is not None:
            message_box_async("Claude Guard 状态详情",
                              "\n".join(evt.detail_lines()))


# os.startfile 编辑白名单属于业务副作用，由 guardian 执行 Command.EDIT_WHITELIST 时调用
def open_config(config_path: str) -> None:
    os.startfile(config_path)  # noqa: S606 - Windows 默认编辑器打开
