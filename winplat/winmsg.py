# -*- coding: utf-8 -*-
"""Win32 MessageBoxW 封装（winplat 薄层）。

用真正的系统弹出窗口替代气泡通知：多行中文原生渲染、置顶显示，
不依赖 win11toast 的气泡生命周期。供两处复用：
- main.py --check 自检结果（frozen windowed exe 下 stdout 不可见）
- tray.py 托盘"状态详情"（独立 daemon 线程弹出，不阻塞托盘消息泵）

MessageBoxW 是按线程模态的：在独立线程调用即为该线程模态，托盘线程
与 guardian 主循环完全不受影响。
"""
import ctypes
import threading

MB_OK = 0x00
MB_ICONERROR = 0x10
MB_ICONINFORMATION = 0x40
MB_SETFOREGROUND = 0x10000
MB_TOPMOST = 0x40000


def message_box(title: str, text: str, *, error: bool = False,
                topmost: bool = True) -> None:
    """阻塞式弹出系统消息框（调用线程内模态）。失败降级为 print。"""
    try:
        flags = MB_OK | (MB_ICONERROR if error else MB_ICONINFORMATION) \
            | MB_SETFOREGROUND
        if topmost:
            flags |= MB_TOPMOST
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
    except Exception:
        print(text)


def message_box_async(title: str, text: str, *, error: bool = False) -> None:
    """daemon 线程弹出消息框，立即返回（托盘回调等 UI 线程用）。"""
    threading.Thread(
        target=message_box, args=(title, text), kwargs={"error": error},
        name="msgbox", daemon=True,
    ).start()
