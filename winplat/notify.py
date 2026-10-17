# -*- coding: utf-8 -*-
"""Toast 通知封装（win11toast）。

Toast 是锦上添花，绝不影响主流程：所有失败静默吞掉，且永不阻塞调用方。
win11toast.toast() 内部 asyncio.run 并 await 消失/点击（短气泡 ~5s、长 ~25s），
同步调用会把 guardian 主循环卡住同样时长（H2）——因此在 daemon 线程异步发射。

本模块刻意零测试（审计 docs/04 TestsDocs 结论已接受）：所有路径都包在
daemon 线程的 try/except 中全吞，无纯逻辑/状态可断言；单测只能 mock
win11toast 断言"线程被启动"，无行为价值。
"""
import threading


def _toast(title: str, body: str, duration: str = "short") -> None:
    """在 daemon 线程中发射 Toast，立即返回。"""
    def _run() -> None:
        try:
            from win11toast import toast

            toast(title, body, duration=duration)
        except Exception:
            pass  # 通知失败不影响主流程

    threading.Thread(target=_run, name="toast", daemon=True).start()


def notify_state(title: str, body: str) -> None:
    """状态变化 Toast（标题 + 正文）。非阻塞。"""
    _toast(title, body, duration="short")


def notify_details(title: str, lines: list) -> None:
    """状态详情：多行文本气泡（T-5 状态详情用）。非阻塞。"""
    _toast(title, "\n".join(lines), duration="long")
