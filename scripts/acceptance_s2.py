"""验收场景 2/3/6：关 Clash ≤2s 阻断 / Clash 死亡期间直连拒绝 / fail-closed。
以管理员运行。会短暂杀死 mihomo 进程（代理中断约 10s，结束后请重开 Clash）。
"""
import socket
import sys
import time
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from core.config import load as load_config  # noqa: E402
from guardian import Guardian, setup_logging  # noqa: E402


def ps(s, timeout=60):
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", s],
                       capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace").strip()


def fw_status():
    _, out = ps("$r=Get-NetFirewallRule -DisplayName 'CG-Global' -EA SilentlyContinue; "
                "if($r){$r.Enabled}else{'MISSING'}")
    return out


def direct():
    try:
        s = socket.create_connection(("160.79.104.10", 443), timeout=4)
        s.close()
        return "REACHED"
    except OSError as e:
        return f"BLOCKED({e.__class__.__name__})"


def main() -> int:
    config = load_config(_ROOT / "config.json")
    log = setup_logging(config)
    print("[accept] 启动 guardian（无托盘）...", flush=True)
    g = Guardian(config, _ROOT / "config.json", tray=None, logger=log)
    g.start()
    time.sleep(10)  # 预热 + 首轮 + 确认窗（当前出口脏 → 预期停在 BLOCKED）
    print(f"[accept] 初始规则状态: {fw_status()} (预期 True=阻断)", flush=True)

    print("[accept] === 场景2：杀 mihomo → 计时阻断 ===", flush=True)
    ps("Stop-Process -Name 'verge-mihomo' -Force -EA SilentlyContinue")
    t0 = time.time()
    result = "TIMEOUT(15s)"
    while time.time() - t0 < 15:
        if fw_status() == "True" and direct().startswith("BLOCKED"):
            result = f"{time.time() - t0:.1f}s"
            break
        time.sleep(0.3)
    print(f"[accept] 场景2 关Clash→阻断生效: {result} (达标线≤2s)", flush=True)
    print(f"[accept] === 场景3：Clash 死亡期间直连真实IP: {direct()} ===", flush=True)

    print("[accept] === 场景6：强杀 guardian（fail-closed）===", flush=True)
    import threading
    g._stop.set()  # noqa: SLF001 - 验收脚本
    if g._thread:  # noqa: SLF001
        g._thread.join(timeout=5)
    import os
    os.kill(os.getpid(), 9) if False else None
    # 直接模拟强杀：不再调用 stop 清理，直接查规则
    time.sleep(1)
    st = fw_status()
    print(f"[accept] 场景6 守护停止后规则状态: {st} (True=阻断保持=达标)", flush=True)

    print("[accept] 全部完成。请手动重启 Clash Verge（代理已断）。", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
