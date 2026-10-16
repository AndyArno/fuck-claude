"""验收场景 2/3/6（修正版）：先等 guardian 到 ALLOWED（规则 Disabled），
再杀 mihomo 从放行态计时阻断——这才是 B-7 的真实形态。
以管理员运行。会短暂杀死 mihomo（代理中断约 15s，结束后请重开 Clash）。
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


def fw_enabled() -> bool:
    _, out = ps("$r=Get-NetFirewallRule -DisplayName 'CG-Global' -EA SilentlyContinue; "
                "if($r){$r.Enabled}else{'MISSING'}")
    return out == "True"


def direct() -> str:
    try:
        s = socket.create_connection(("160.79.104.10", 443), timeout=4)
        s.close()
        return "REACHED"
    except OSError as e:
        return f"BLOCKED({e.__class__.__name__})"


def main() -> int:
    config = load_config(_ROOT / "config.json")
    log = setup_logging(config)
    g = Guardian(config, _ROOT / "config.json", tray=None, logger=log)
    g.start()

    # 1) 等 ALLOWED：规则 Disabled（确认窗 3 次 × slow 5s + 起始对齐，上限 90s）
    print("[accept] 等 guardian 进入 ALLOWED（出口须在白名单）...", flush=True)
    deadline = time.time() + 90
    reached_allowed = False
    while time.time() < deadline:
        st = g._gstate.state  # noqa: SLF001
        if st == "ALLOWED":
            reached_allowed = True
            break
        time.sleep(1)
    if not reached_allowed:
        print(f"[accept] FAIL: 90s 内未到 ALLOWED（当前 {g._gstate.state}）——出口不在白名单则无法测放行态", flush=True)  # noqa: SLF001
        g.stop()
        return 1
    print(f"[accept] 已到 ALLOWED，规则 Enabled={fw_enabled()} (预期 False)", flush=True)

    # 2) 杀 mihomo → 从放行态计时阻断
    print("[accept] === 场景2：从 ALLOWED 杀 mihomo，计时阻断 ===", flush=True)
    t_kill = time.time()
    ps("Stop-Process -Name 'verge-mihomo' -Force -EA SilentlyContinue")
    result = "TIMEOUT(15s)"
    while time.time() - t_kill < 15:
        if fw_enabled() and direct().startswith("BLOCKED"):
            result = f"{time.time() - t_kill:.1f}s"
            break
        time.sleep(0.2)
    print(f"[accept] 场景2 ALLOWED→阻断: {result} (达标线≤2s)", flush=True)
    print(f"[accept] 场景3 Clash死亡期间直连真实IP: {direct()}", flush=True)

    # 3) fail-closed：模拟强杀（不再 stop()，直接查规则）
    print("[accept] === 场景6：守护停止后规则状态（fail-closed）===", flush=True)
    import os
    os._exit(0) if False else None
    g._stop.set()  # noqa: SLF001
    time.sleep(2)
    print(f"[accept] 场景6 规则 Enabled={fw_enabled()} (True=阻断保持=达标)", flush=True)
    print("[accept] 完成。请重启 Clash Verge（代理已断）。", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
