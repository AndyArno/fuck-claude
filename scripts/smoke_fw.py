"""Claude Guard 防火墙冒烟脚本。

流程：建双规则 →（若管理员）阻断验证→放行验证→存量 TCP 连接行为实测 → 清理。
非管理员运行时打印跳过原因，仅验证 PS 调用与错误处理路径，退出码 0。
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys

PS_TIMEOUT = 10


def ps(script: str) -> str:
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    proc = subprocess.run(cmd, capture_output=True, timeout=PS_TIMEOUT)

    def _dec(data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("mbcs", "replace")

    if proc.returncode != 0:
        raise RuntimeError(f"PS exit {proc.returncode}: {_dec(proc.stderr or b'').strip() or _dec(proc.stdout or b'').strip()}")
    return _dec(proc.stdout).strip()


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def connect_result(host: str = "claude.ai", port: int = 443, timeout: float = 5.0) -> str:
    """返回 'REACHED' / 'REFUSED' / 'ERROR:<msg>'。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "REACHED"
    except OSError as exc:
        return f"REFUSED ({exc.__class__.__name__})"


def main() -> int:
    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    v4, v6 = cfg["rule_name_v4"], cfg["rule_name_v6"]
    admin = is_admin()
    print(f"[smoke_fw] admin={admin}")

    # 1. 建双规则（非管理员下预期 PermissionDenied/超时 → 走跳过路径）
    print("[smoke_fw] creating CG-Global + CG-V6 ...")
    try:
        ps(
            "$n=" + _q(v4) + ";"
            "if (Get-NetFirewallRule -DisplayName $n -EA SilentlyContinue){Remove-NetFirewallRule -DisplayName $n};"
            "New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -Enabled True"
            " -Protocol TCP -RemoteAddress " + _q(",".join(cfg["blocked_cidrs_v4"])) + "|Out-Null"
        )
        ps(
            "$n=" + _q(v6) + ";"
            "if (Get-NetFirewallRule -DisplayName $n -EA SilentlyContinue){Remove-NetFirewallRule -DisplayName $n};"
            "New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -Enabled True"
            " -Protocol TCP -RemoteAddress " + _q(",".join(cfg["blocked_cidrs_v6"])) + "|Out-Null"
        )
    except subprocess.TimeoutExpired:
        if not admin:
            print("[smoke_fw] SKIP: rule creation timed out (UAC/non-admin shell).")
            print("[smoke_fw] verified: PS invocation path + timeout handling OK.")
            return 0
        print("[smoke_fw] rule creation timed out unexpectedly as admin.")
        return 1
    except Exception as exc:
        if not admin:
            print(f"[smoke_fw] SKIP: non-admin rule creation rejected as expected: {exc}")
            print("[smoke_fw] verified: PS invocation + permission-error path OK.")
            return 0
        print(f"[smoke_fw] rule creation failed: {exc}")
        return 1
    print("[smoke_fw] both rules created.")

    if not admin:
        print("[smoke_fw] SKIP: not running as Administrator.")
        print("[smoke_fw]   skipped checkpoints (need elevation):")
        print("[smoke_fw]   - blocking verification (Enable → claude.ai unreachable)")
        print("[smoke_fw]   - allow verification (Disable → claude.ai reachable)")
        print("[smoke_fw]   - pre-existing TCP connection behavior on Enable")
        print("[smoke_fw]   - rule status readback / cleanup delete")
        print("[smoke_fw] verified in this run: PS invocation + creation error path only.")
        return 0

    # 2. 阻断验证
    print(f"[smoke_fw] BLOCKED phase: {connect_result()}")
    # 3. 放行验证
    print("[smoke_fw] disabling CG-Global ...")
    ps("Disable-NetFirewallRule -DisplayName " + _q(v4))
    print(f"[smoke_fw] ALLOWED phase: {connect_result()}")

    # 4. 存量 TCP 连接行为实测
    print("[smoke_fw] opening TCP connection to claude.ai for existing-conn test ...")
    try:
        s = socket.create_connection(("claude.ai", 443), timeout=5)
    except OSError as exc:
        print(f"[smoke_fw] SKIP existing-conn test: pre-open failed ({exc})")
        s = None
    if s is not None:
        ps("Enable-NetFirewallRule -DisplayName " + _q(v4))
        s.setblocking(False)
        import select
        r, _, _ = select.select([s], [], [], 3.0)
        if not r:
            try:
                s.send(b"")
                print("[smoke_fw] existing connection: STILL ALIVE after Enable")
            except OSError as exc:
                print(f"[smoke_fw] existing connection: DEAD after Enable ({exc.__class__.__name__})")
        else:
            data = s.recv(1, socket.MSG_PEEK)
            print("[smoke_fw] existing connection:", "DEAD (0-byte peek)" if data == b"" else "ALIVE (data pending)")
        s.close()

    # 5. 清理
    print("[smoke_fw] cleanup: removing both rules ...")
    ps("Remove-NetFirewallRule -DisplayName " + _q(v4) + " -EA SilentlyContinue")
    ps("Remove-NetFirewallRule -DisplayName " + _q(v6) + " -EA SilentlyContinue")
    print("[smoke_fw] done.")
    return 0


def _q(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


if __name__ == "__main__":
    sys.exit(main())
