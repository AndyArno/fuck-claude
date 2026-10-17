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
from winplat.winmsg import LiveMessageBox
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
    END_OVERRIDE = "end_override"   # 立即结束临时放行，恢复阻断
    TOGGLE_PAUSE = "toggle_pause"   # 暂停/恢复切换（菜单合并为单项）
    PAUSE = "pause"                 # 兼容旧命令值（热键/脚本）
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
    # 白名单命中三态：True=命中 False=不在白名单 None=未探测
    whitelist_hit: bool | None = None
    # 检查⑤ DNS 出口探针看到的解析出口 IP（仅确认泄漏时携带）
    dns_leak_ip: str | None = None
    # 检查结果：名称 -> True/False/None（None=未探测）
    checks: dict = field(default_factory=dict)
    paused: bool = False
    drift: bool = False
    override_active: bool = False
    # 临时放行剩余分钟（None=非 override）；-1 保留为"未知"哨兵
    override_min_left: int | None = None
    # 临时放行总时长（分钟，来自配置；菜单文案用，曾硬编码 30）
    override_minutes: int = 30
    confirming: bool = False

    def _status(self) -> Status:
        c = self.checks
        dns_leak = self.dns_leak_ip if c.get("DNS出口干净") is False else None
        return Status(
            blocking=self.state is State.BLOCKED,
            paused=self.paused,
            override_min_left=(self.override_min_left
                               if self.override_min_left is not None
                               else (-1 if self.override_active else None)),
            confirming=self.confirming,
            proxy_ok=c.get("mihomo进程"),
            tunnel_ok=c.get("TUN网卡"),
            dns_ok=c.get("fake-ip"),
            dns_egress_ok=c.get("DNS出口干净"),
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
        # 临时放行 = 规则已放行（计划内）：红图标会与"流量实际放行"
        # 矛盾，用黄色提示"非常规状态"
        if self.override_active:
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
        # 三态：未探测不断言"否"（用户会读成"被查过且不在白名单"）
        hit_txt = {True: "是", False: "否"}.get(self.whitelist_hit, "未探测")
        lines.append(f"白名单命中: {hit_txt}")
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
        # 详情弹窗（LiveMessageBox）：开着期间随事件实时刷新正文；
        # None = 当前没有打开的详情窗
        self._detail_box: "LiveMessageBox | None" = None
        self._detail_lock = threading.Lock()
        # guardian 注册的唤醒回调：托盘投递命令时立即调用（Event.set），
        # 主循环从 _sleep 中被唤醒，命令毫秒级处理（不等下轮 fast tick）
        self._on_command: "callable[[], None] | None" = None

    # ---- guardian 侧接口 -------------------------------------------------

    def start(self) -> None:
        self._icon = _DblClickIcon(
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
        # 先更新 _last_event 再重建菜单：菜单项的 visible/checked/enabled
        # lambda 读的是 _last_event，顺序反了菜单显示旧状态（✔ 滞后一轮，
        # 用户实测"不跟手"）。
        self._last_event = evt
        if self._icon is not None:  # 测试环境未 run_detached 时跳过 UI 更新
            color = evt.icon_color()
            img = self._icons[color]
            if self._icon.icon is not img:
                self._icon.icon = img
            self._icon.title = evt.tooltip()
            # 状态变化 → 重建菜单（暂停✔/临时放行项的 visible/enabled
            # 依赖 _last_event；不重建会显示过期状态）
            try:
                self._icon.update_menu()
            except Exception:
                pass  # 菜单更新失败不影响守护
        # 详情窗开着期间实时刷新（状态变化/新检查结果立即反映）
        with self._detail_lock:
            if self._detail_box is not None and not self._detail_box.closed:
                self._detail_box.refresh(
                    "Claude Guard 状态详情",
                    "\n".join(evt.detail_lines()))

    def _menu_cb(self, cmd: Command):
        def callback(icon, item):
            self.commands.put(cmd)  # 只投递，不执行业务
            # 立即唤醒 guardian 主循环：命令毫秒级被处理，不等下轮 tick
            if self._on_command is not None:
                self._on_command()

        return callback

    def _paused(self) -> bool:
        return bool(self._last_event and self._last_event.paused)

    def _on_override(self) -> bool:
        return bool(self._last_event and self._last_event.override_active)

    def _override_label(self) -> str:
        """临时放行菜单文案：分钟数取 guardian 送达的配置值（曾硬编码
        "30 分钟"，用户改 override_minutes 后菜单与实际时长不符）。"""
        minutes = 30
        if self._last_event is not None:
            minutes = self._last_event.override_minutes
        return f"临时放行 {minutes} 分钟"

    def _build_menu(self) -> pystray.Menu:
        """动态菜单：visible/checked 接 callable，pystray 打开菜单时求值；
        状态变化时 _apply 里 update_menu() 重建，保证与守护状态一致。"""
        return pystray.Menu(
            pystray.MenuItem(
                "状态详情", self._show_details, default=True
            ),
            pystray.MenuItem(
                self._override_label(),
                self._menu_cb(Command.OVERRIDE_30MIN),
                # 已在临时放行中 → 置灰防重复点击
                enabled=lambda item: not self._on_override(),
            ),
            pystray.MenuItem(
                "立即恢复阻断",
                self._menu_cb(Command.END_OVERRIDE),
                # 仅临时放行中出现（平时隐藏，语义清晰）
                visible=lambda item: self._on_override(),
            ),
            pystray.MenuItem(
                # 原生左侧勾选标记（MFS_CHECKED）表示暂停状态，
                # 文字保持稳定不随状态变——同截图 TUN 模式的样式
                "暂停守护",
                self._menu_cb(Command.TOGGLE_PAUSE),
                checked=lambda item: self._paused(),
            ),
            pystray.MenuItem("编辑白名单", self._menu_cb(Command.EDIT_WHITELIST)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出（恢复阻断）", self._menu_cb(Command.EXIT)),
        )

    def _show_details(self, icon, item) -> None:
        """状态详情（左键双击或菜单"状态详情"）：弹实时窗口。

        LiveMessageBox 弹出后随每次托盘事件刷新正文（见 _apply）：
        窗口开着期间出口 IP / 检查结果变化立即反映，直到用户点确定。
        已有窗口打开时仅刷新（不重复弹窗）。"""
        self.commands.put(Command.SHOW_DETAILS)
        evt = self._last_event
        if evt is None:
            return
        with self._detail_lock:
            if self._detail_box is not None and not self._detail_box.closed:
                self._detail_box.refresh(
                    "Claude Guard 状态详情",
                    "\n".join(evt.detail_lines()))
                return
            self._detail_box = LiveMessageBox(
                "Claude Guard 状态详情",
                "\n".join(evt.detail_lines()))


# os.startfile 编辑白名单属于业务副作用，由 guardian 执行 Command.EDIT_WHITELIST 时调用


class _DblClickIcon(pystray.Icon):
    """左键双击才触发的托盘图标（防单击误触）。

    pystray/_win32 默认 WM_LBUTTONUP（单击）即激活默认菜单项。本类
    重写 _on_notify：忽略 WM_LBUTTONUP（0x202），仅 WM_LBUTTONDBLCLK
    （0x203）激活。Windows 双击序列 DOWN→UP→DBLCLK→UP 中的首个 UP
    被忽略，故单击不再弹详情；右键菜单行为不变（基类处理）。
    """

    def _on_notify(self, wparam, lparam):
        if lparam == 0x203:  # WM_LBUTTONDBLCLK
            self()
        elif self._menu_handle and lparam == 0x205:  # WM_RBUTTONUP
            super()._on_notify(wparam, lparam)
        # WM_LBUTTONUP（0x202）刻意不响应：防单击误触（用户实测反馈）


def open_config(config_path: str) -> None:
    os.startfile(config_path)  # noqa: S606 - Windows 默认编辑器打开
