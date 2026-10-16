"""完整验收：场景 1→2→3→6 串跑。
流程：脏环境启动 guardian（应阻断）→ 起 Clash（应放行）→ 停服务杀内核（计时阻断）
→ 停守护验证 fail-closed。结束后提示手动重开 Clash。
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from core.config import load as load_config  # noqa: E402
from guardian import Guardian, setup_logging  # noqa: E402


def ps(s, timeout=60):
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", s],
                   capture_output=True, timeout=timeout)


def fw_enabled() -> bool:
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$r=Get-NetFirewallRule -DisplayName 'CG-Global' -EA SilentlyContinue; "
         "if($r){$r.Enabled}else{'MISSING'}"],
        capture_output=True, timeout=60)
    return (p.stdout or b"").decode().strip() == "True"


def direct() -> str:
    try:
        s = socket.create_connection(("160.79.104.10", 443), timeout=4)
        s.close()
        return "REACHED"
    except OSError:
        return "BLOCKED"


def mihomo_pid() -> str:
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "Get-Process verge-mihomo -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, timeout=30)
    return (p.stdout or b"").decode().strip()


def main() -> int:
    config = load_config(_ROOT / "config.json")
    log = setup_logging(config)
    g = Guardian(config, _ROOT / "config.json", tray=None, logger=log)
    g.start()
    print("[1] guardian 启动（mihomo 已死，预期阻断）", flush=True)
    time.sleep(4)
    print(f"[1] state={g._gstate.state} fw={fw_enabled()} direct={direct()}", flush=True)  # noqa: SLF001

    print("[2] 启动 Clash 服务 + 内核 ...", flush=True)
    ps("Start-Service clash_verge_service")
    time.sleep(4)
    pid = mihomo_pid()
    print(f"[2] mihomo pid: {pid or '未运行——请手动打开 Clash Verge 界面'}", flush=True)
    if not pid:
        # 服务模式可能不自动拉内核，等用户手动
        deadline = time.time() + 60
        while time.time() < deadline and not mihomo_pid():
            time.sleep(2)
        pid = mihomo_pid()
        print(f"[2] mihomo pid now: {pid or '仍未运行'}", flush=True)
        if not pid:
            g.stop()
            return 1

    t0 = time.time()
    while time.time() - t0 < 90 and g._gstate.state != "ALLOWED":  # noqa: SLF001
        time.sleep(1)
    print(f"[2] state={g._gstate.state}（预期 ALLOWED）fw={fw_enabled()} direct={direct()}", flush=True)  # noqa: SLF001
    if g._gstate.state != "ALLOWED":  # noqa: SLF001
        g.stop()
        return 1

    print("[3] === 场景2：停服务 + 杀内核，计时阻断 ===", flush=True)
    t_kill = time.time()
    ps("Stop-Service clash_verge_service -Force")
    ps("Stop-Process -Name 'verge-mihomo' -Force -EA SilentlyContinue")
    result = "TIMEOUT(15s)"
    while time.time() - t_kill < 15:
        if fw_enabled() and direct() == "BLOCKED":
            result = f"{time.time() - t_kill:.1f}s"
            break
        time.sleep(0.2)
    print(f"[3] 场景2 ALLOWED→阻断: {result}（达标线≤2s）", flush=True)
    print(f"[3] 场景3 Clash 死亡期间直连: {direct()}", flush=True)

    print("[4] === 场景6：守护停止后规则保持 ===", flush=True)
    g._stop.set()  # noqa: SLF001
    time.sleep(2)
    print(f"[4] fw={fw_enabled()}（True=达标）direct={direct()}", flush=True)
    print("[done] 请手动重启 Clash Verge。", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
