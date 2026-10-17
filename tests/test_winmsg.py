# -*- coding: utf-8 -*-
"""winmsg LiveMessageBox.refresh 测试（P3-9）：标题/正文各自判变分别更新。

Win32 调用全 mock；绕过线程弹窗，直接构造对象并注入句柄状态。
"""
import threading

import pytest

from winplat import winmsg


def make_live(monkeypatch, *, dlg=100, ctrl=200, closed=False):
    """构造跳过线程弹窗的 LiveMessageBox，注入已定位的句柄。"""
    box = winmsg.LiveMessageBox.__new__(winmsg.LiveMessageBox)
    box._title = "旧标题"
    box._text = "旧正文"
    box._tid = 1234
    box._dlg = dlg
    box._ctrl = ctrl
    box._closed = threading.Event()
    if closed:
        box._closed.set()
    return box


class FakeUser32:
    def __init__(self):
        self.calls = []

    def SetWindowTextW(self, hwnd, text):
        self.calls.append(("title", hwnd, text))

    def SendMessageW(self, hwnd, msg, wparam, lparam):
        self.calls.append(("body", hwnd, lparam))


@pytest.fixture
def fake_user32(monkeypatch):
    u = FakeUser32()
    monkeypatch.setattr(winmsg.ctypes, "windll",
                        type("W", (), {"user32": u, "kernel32": None})())
    return u


def test_title_only_change_refreshes_title(fake_user32):
    """P3-9：正文不变仅标题变化 → SetWindowTextW 被调用（原实现不刷）。"""
    box = make_live(None)
    box.refresh("新标题", "旧正文")
    assert ("title", 100, "新标题") in fake_user32.calls
    assert all(c[0] != "body" for c in fake_user32.calls)
    assert box._title == "新标题" and box._text == "旧正文"


def test_body_only_change_refreshes_body(fake_user32):
    box = make_live(None)
    box.refresh("旧标题", "新正文")
    assert ("body", 200, "新正文") in fake_user32.calls
    assert all(c[0] != "title" for c in fake_user32.calls)


def test_both_change_refresh_both(fake_user32):
    box = make_live(None)
    box.refresh("新标题", "新正文")
    kinds = {c[0] for c in fake_user32.calls}
    assert kinds == {"title", "body"}


def test_no_change_is_noop(fake_user32):
    box = make_live(None)
    box.refresh("旧标题", "旧正文")
    assert fake_user32.calls == []


def test_closed_window_refresh_noop(fake_user32):
    """窗口已关闭 → 静默 no-op，不抛不调用 Win32。"""
    box = make_live(None, closed=True)
    box.refresh("新标题", "新正文")
    assert fake_user32.calls == []
