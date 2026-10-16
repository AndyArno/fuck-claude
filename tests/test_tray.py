# -*- coding: utf-8 -*-
"""tray.py 状态详情窗口单测：不真弹窗，只断言内容与调用方式。"""
from __future__ import annotations

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
        """状态详情点菜单 → 弹真窗口（message_box_async），内容为全部行。"""
        shown = []
        import tray
        monkeypatch.setattr(
            tray, "message_box_async",
            lambda title, text: shown.append((title, text)))
        t = Tray()
        t._last_event = _event()
        t._show_details(None, None)
        title, text = shown[0]
        assert title == "Claude Guard 状态详情"
        assert text == "\n".join(_event().detail_lines())
        assert t.commands.get_nowait() is Command.SHOW_DETAILS
