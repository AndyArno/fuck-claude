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



class LiveMessageBox:
    """可实时刷新正文的消息框（托盘"状态详情"专用）。

    MessageBoxW 本身内容静态；本类在 daemon 线程弹出后记录其线程 ID，
    外部调用 refresh(text) 通过 GetDlgItem(dlg, 0xFFFF) 拿到正文静态
    控件并 WM_SETTEXT 改写（实测 Windows 11 可行），实现"窗口开着，
    数据每秒变"。标题随正文一起刷新。

    线程安全：refresh 与弹窗线程通过句柄交互，句柄在弹窗建立后由
    _locate() 抓取；窗口已关闭时 refresh 静默 no-op（句柄失效）。
    """

    def __init__(self, title: str, text: str) -> None:
        self._title = title
        self._text = text
        self._tid: int | None = None
        self._dlg: int | None = None
        self._ctrl: int | None = None
        self._closed = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="live-msgbox", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self._tid = ctypes.windll.kernel32.GetCurrentThreadId()
        try:
            flags = MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST
            ctypes.windll.user32.MessageBoxW(
                None, self._text, self._title, flags)
        finally:
            self._closed.set()

    def _locate(self) -> None:
        """枚举弹窗线程的顶层窗口，抓 #32770 对话框及其正文控件。"""
        if self._tid is None or self._dlg is not None:
            return
        import ctypes.wintypes as w

        found: dict[str, int] = {}

        def cb(hwnd, _lparam):
            cls = ctypes.create_unicode_buffer(64)
            ctypes.windll.user32.GetClassNameW(hwnd, cls, 64)
            if cls.value == "#32770":
                found["dlg"] = hwnd
                return False  # 找到即停
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        ctypes.windll.user32.EnumThreadWindows(self._tid, WNDENUMPROC(cb), 0)
        dlg = found.get("dlg")
        if dlg:
            self._dlg = dlg
            self._ctrl = ctypes.windll.user32.GetDlgItem(dlg, 0xFFFF)

    def refresh(self, title: str, text: str) -> None:
        """更新窗口标题与正文；窗口已关闭则静默忽略。"""
        if self._closed.is_set():
            return
        self._locate()
        if self._dlg and self._ctrl:
            user32 = ctypes.windll.user32
            if text != self._text:
                user32.SetWindowTextW(self._dlg, title)
                user32.SendMessageW(self._ctrl, 0x000C, 0, text)  # WM_SETTEXT
                self._text = text

    @property
    def closed(self) -> bool:
        return self._closed.is_set()
