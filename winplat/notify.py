# -*- coding: utf-8 -*-
"""Toast 通知封装（win11toast）。

所有失败静默吞掉：Toast 是锦上添花，绝不影响主流程。
可在任意线程调用（win11toast 内部自管）。
"""
import threading

_toast_lock = threading.Lock()


def _toast(title: str, body: str, duration: str = "short") -> None:
    try:
        from win11toast import toast

        with _toast_lock:
            toast(title, body, duration=duration)
    except Exception:
        pass  # 通知失败不影响主流程


def notify_state(title: str, body: str) -> None:
    """状态变化 Toast（标题 + 正文）。"""
    _toast(title, body, duration="short")


def notify_details(title: str, lines: list) -> None:
    """状态详情：多行文本气泡（T-5 状态详情用）。"""
    _toast(title, "\n".join(lines), duration="long")
