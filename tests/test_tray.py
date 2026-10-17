# -*- coding: utf-8 -*-
"""tray.py 状态详情窗口单测：不真弹窗，只断言内容与调用方式。"""
from __future__ import annotations

import pytest

from core.messages import TECH_SEPARATOR
from tray import Command, State, StateEvent, Tray


def _event() -> StateEvent:
    return StateEvent(
        state=State.BLOCKED,
        exit_ip="203.0.113.10",
        whitelist_hit=False,
        checks={
            "mihomo进程": True,
            "TUN网卡": True,
            "fake-ip": False,
            "echo出口": None,
        },
    )


class TestDetailLines:
    def test_detail_lines_full_structure(self):
        lines = _event().detail_lines()
        assert lines[0]  # 第一行：防火墙状态（大白话）
        assert len(lines) >= 9
        assert TECH_SEPARATOR in lines
        assert lines.index(TECH_SEPARATOR) < lines.index("状态: 阻断")
        assert "出口 IP: 203.0.113.10" in lines
        assert "白名单命中: 否" in lines
        # 五项检查：通过/未通过/未探测
        assert "mihomo进程: 通过" in lines
        assert "TUN网卡: 通过" in lines
        assert "fake-ip: 未通过" in lines
        assert "echo出口: 未探测" in lines

    def test_detail_lines_multiline_joined(self, monkeypatch):
        """状态详情（双击/菜单）→ LiveMessageBox 弹实时窗，内容为全部行。"""
        boxes = []

        class FakeBox:
            def __init__(self, title, text):
                self.title = title
                self.text = text
                self.refreshed = []
                self.closed = False

            def refresh(self, title, text):
                self.refreshed.append((title, text))

        import tray as _tray
        monkeypatch.setattr(_tray, "LiveMessageBox", FakeBox)
        t = Tray()
        t._last_event = _event()
        t._show_details(None, None)
        assert t.commands.get_nowait() is Command.SHOW_DETAILS
        box = t._detail_box
        assert box.title == "Claude Guard 状态详情"
        assert box.text == "\n".join(_event().detail_lines())

    def test_detail_window_live_refresh(self, monkeypatch):
        """实时刷新：详情窗开着时新事件到达 → refresh 被调，不重复弹窗。"""
        boxes = []

        class FakeBox:
            def __init__(self, title, text):
                self.title = title
                self.text = text
                self.refreshed = []
                self.closed = False

            def refresh(self, title, text):
                self.refreshed.append(text)

        import tray
        monkeypatch.setattr(tray, "LiveMessageBox", FakeBox)
        t = Tray()
        t._last_event = _event()
        t._show_details(None, None)
        box = t._detail_box
        assert box is not None
        # 新事件（检查结果变化）→ 已开的窗被刷新
        evt2 = StateEvent(
            state=State.BLOCKED,
            exit_ip="198.51.100.7",
            checks={"mihomo进程": True, "TUN网卡": True,
                    "fake-ip": True, "echo出口": True},
        )
        t._apply(evt2)
        assert len(box.refreshed) == 1
        assert "198.51.100.7" in box.refreshed[0]
        # 窗开着时再双击 → 不弹第二个窗，仅刷新
        t._last_event = evt2
        t._show_details(None, None)
        assert t._detail_box is box
        assert len(box.refreshed) == 2


class TestStartupConfirming:
    """启动确认期文案回归：检查全过但仍在拦截时，不得显示"环境正常"。"""

    def _confirming_event(self) -> StateEvent:
        return StateEvent(
            state=State.BLOCKED,
            exit_ip="203.0.113.10",
            whitelist_hit=True,
            checks={
                "mihomo进程": True,
                "TUN网卡": True,
                "fake-ip": True,
                "echo出口": True,
                "DNS出口干净": True,
            },
            confirming=True,
        )

    def test_confirming_reason_not_normal(self):
        """确认期：原因行显示确认中，而不是矛盾的"代理环境正常"。"""
        joined = "\n".join(self._confirming_event().detail_lines())
        assert "代理环境正常" not in joined
        assert "确认" in joined

    def test_confirming_status_line(self):
        lines = self._confirming_event().detail_lines()
        assert "启动确认中" in lines[0] or "确认中" in lines[0]

    def test_not_confirming_keeps_normal_text(self):
        """非确认期（稳定拦截）不误加确认文案：无 confirming 字段时行为不变。"""
        evt = self._confirming_event()
        evt2 = StateEvent(
            state=evt.state, exit_ip=evt.exit_ip,
            whitelist_hit=evt.whitelist_hit, checks=evt.checks,
        )
        assert "启动确认中" not in "\n".join(evt2.detail_lines())


class TestApplySurvivesBadEvent:
    """P1-1 回归：_apply 内部抛异常（如曾经的 tooltip NameError）不得杀托盘线程，
    也不得让 _last_event 停更——事件语义固定为"尽力应用，失败记日志"。"""

    @staticmethod
    def _icon():
        """_apply 只有在 _icon 非 None 时才走 tooltip/update_menu（:203）。
        未 start() 的 Tray._icon 是 None，坏事件根本到不了 tooltip——
        用最小 fake icon 把 UI 路径接通。"""

        class FakeIcon:
            icon = None
            title = ""

            def update_menu(self):
                pass

        return FakeIcon()

    def test_apply_raises_and_event_loop_survives(self, caplog):
        """语义对齐设计（05 方案）：_apply 不吞 UI 异常（真实异常应暴露），
        吞+记日志的是 _event_loop。断言三层：异常传出 _apply、
        loop 吞掉继续、_last_event 已更新。"""
        import logging
        t = Tray()
        t._icon = self._icon()
        evt = _event()
        evt.tooltip = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        with pytest.raises(RuntimeError):
            t._apply(evt)
        assert t._last_event is evt  # _last_event 先于 UI 更新（顺序契约）
        with caplog.at_level(logging.ERROR, logger="claude-guard.tray"):
            t.events.put(evt)
            t.events.put(None)
            t._event_loop()
        assert any("托盘状态应用失败" in r.message for r in caplog.records)

    def test_event_loop_survives_apply_exception(self, caplog):
        """_event_loop 吞异常但记日志（不再静默 pass）。"""
        import logging
        t = Tray()
        t._icon = self._icon()
        bad = _event()
        bad.tooltip = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        good = _event()
        with caplog.at_level(logging.ERROR, logger="claude-guard.tray"):
            t.events.put(bad)
            t.events.put(good)
            t.events.put(None)  # 哨兵：处理完即停
            t._event_loop()
        assert t._last_event is good  # 坏事件没杀死循环，好事件照常应用
        assert any("托盘状态应用失败" in r.message for r in caplog.records)
