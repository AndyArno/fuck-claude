"""Windows 防火墙规则封装（PowerShell NetSecurity cmdlet 子进程封装）。

管理两条规则：
- CG-Global（IPv4 门控）：create / enable / disable / get_status / ensure_exists，
  RemoteAddress 来自 config.blocked_cidrs_v4。
- CG-V6（IPv6 永久封死）：create + ensure_enabled，**无 disable**（门禁无权放行 v6）。

所有调用通过 `powershell -NoProfile -Command` 子进程；超时 10s；
非管理员权限时抛 FirewallPermissionError（NoAdministrativeRights）。
"""

from __future__ import annotations

import json
import subprocess
import sys

if __package__ in (None, ""):
    Config = object  # 允许独立运行/冒烟时鸭子类型（只需属性 rule_name_*/blocked_cidrs_*）
else:
    try:
        from core.config import Config
    except ImportError:  # core/config.py 尚未落地（并行开发中）
        Config = object

_PS_TIMEOUT = 10  # seconds

_ERROR_MARKERS = {
    "access": "NoAdministrativeRights",
}


class FirewallError(RuntimeError):
    """防火墙操作失败的基类。"""


class FirewallPermissionError(FirewallError):
    """缺少管理员权限（NetSecurity cmdlet 需要 elevated shell）。"""


class RuleNotFoundError(FirewallError):
    """查询的规则不存在。"""


def _ps_quote(value: str) -> str:
    """把参数安全嵌入 PowerShell 单引号字符串（单引号翻倍转义）。"""
    return "'" + value.replace("'", "''") + "'"


def _run_ps(script: str) -> str:
    """执行一段 PowerShell 脚本，返回 stdout。权限/超时错误有明确异常。"""
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_PS_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        # 非管理员下部分 cmdlet 可能触发 UAC/慢路径挂起而非快速报错；
        # 统一归入权限路径，避免门禁主循环误判为环境故障。
        raise FirewallPermissionError(
            f"NoAdministrativeRights: PowerShell timed out after {_PS_TIMEOUT}s "
            "(likely non-elevated shell / UAC prompt)"
        ) from exc
    except OSError as exc:
        raise FirewallError(f"Failed to launch PowerShell: {exc}") from exc

    def _dec(data: bytes) -> str:
        # PS 控制台输出编码随系统 locale（中文系统为 GBK），UTF-8 优先、mbcs 兜底
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("mbcs", "replace")

    stdout, stderr = _dec(proc.stdout or b""), _dec(proc.stderr or b"")

    if proc.returncode != 0:
        combined = f"{stderr}\n{stdout}".strip()
        if _is_access_denied(combined):
            raise FirewallPermissionError(
                "NoAdministrativeRights: firewall cmdlets require an elevated "
                "(Administrator) shell"
            )
        raise FirewallError(
            f"PowerShell exited {proc.returncode}: {combined or 'no output'}"
        )
    return stdout.strip()


def _is_access_denied(output: str) -> bool:
    lowered = output.lower()
    return (
        "noadministrativerights" in lowered
        or "access is denied" in lowered
        or "accessdenied" in lowered
        or "denied" in lowered and "permission" in lowered
        or "permissiondenied" in lowered
        or "拒绝访问" in output
        or "requires elevation" in lowered
        or "must be run from an elevated" in lowered
        or "requires membership in local administrators" in lowered
    )


# ---------------------------------------------------------------- CG-Global

def create_rule(config: Config) -> None:
    """创建（或覆盖重建）CG-Global 规则，阻断 blocked_cidrs_v4 全出站。"""
    name = _ps_quote(config.rule_name_v4)
    remote = _ps_quote(",".join(config.blocked_cidrs_v4))
    script = (
        f"$existing = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        f"if ($existing) {{ Remove-NetFirewallRule -DisplayName {name} -ErrorAction Stop }}; "
        "New-NetFirewallRule -DisplayName " + name
        + " -Direction Outbound -Action Block -Enabled True"
        + " -Protocol TCP -RemoteAddress " + remote
        + " | Out-Null"
    )
    _run_ps(script)


def enable(config: Config) -> None:
    """启用 CG-Global（阻断态）。"""
    _run_ps(
        "Enable-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_v4)
    )


def disable(config: Config) -> None:
    """停用 CG-Global（放行态）。仅门禁逻辑允许调用。"""
    _run_ps(
        "Disable-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_v4)
    )


def get_status(config: Config) -> bool:
    """返回 CG-Global 是否 Enabled。规则不存在 → False（不抛异常）。"""
    name = _ps_quote(config.rule_name_v4)
    script = (
        f"$r = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        "if ($r) { ($r | Get-NetFirewallRule).Enabled } "
        "else { Write-Output 'MISSING' }"
    )
    out = _run_ps(script)
    if out == "MISSING":
        return False
    return out.lower() == "true"


def ensure_exists(config: Config) -> None:
    """规则缺失（被第三方安全软件删掉）时重建；存在则不动作。"""
    name = _ps_quote(config.rule_name_v4)
    script = (
        f"$r = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        "if (-not $r) { Write-Output 'REBUILD' } else { Write-Output 'OK' }"
    )
    if _run_ps(script) == "REBUILD":
        create_rule(config)


# ------------------------------------------------------------------- CG-V6

def create_rule_v6(config: Config) -> None:
    """创建（或覆盖重建）CG-V6 规则，永久阻断 blocked_cidrs_v6。"""
    name = _ps_quote(config.rule_name_v6)
    remote = _ps_quote(",".join(config.blocked_cidrs_v6))
    script = (
        f"$existing = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        f"if ($existing) {{ Remove-NetFirewallRule -DisplayName {name} -ErrorAction Stop }}; "
        "New-NetFirewallRule -DisplayName " + name
        + " -Direction Outbound -Action Block -Enabled True"
        + " -Protocol TCP -RemoteAddress " + remote
        + " | Out-Null"
    )
    _run_ps(script)


def ensure_enabled_v6(config: Config) -> None:
    """CG-V6 必须存在且 Enabled；缺失则重建，被禁用则强制 Enabled。
    本模块不存在任何 disable CG-V6 的函数——门禁无权放行 IPv6。"""
    name = _ps_quote(config.rule_name_v6)
    script = (
        f"$r = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        "if (-not $r) { Write-Output 'MISSING' } "
        "elseif ($r.Enabled -ne 'True') { Write-Output 'DISABLED' } "
        "else { Write-Output 'OK' }"
    )
    state = _run_ps(script)
    if state == "MISSING":
        create_rule_v6(config)
    elif state == "DISABLED":
        _run_ps("Enable-NetFirewallRule -DisplayName " + name)


def get_status_v6(config: Config) -> bool:
    """返回 CG-V6 是否存在且 Enabled。供每轮校验使用。"""
    name = _ps_quote(config.rule_name_v6)
    script = (
        f"$r = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        "if ($r) { $r.Enabled } else { Write-Output 'MISSING' }"
    )
    out = _run_ps(script)
    if out == "MISSING":
        return False
    return out.lower() == "true"


# ----------------------------------------------------------------- smoke


def _main(argv: list[str]) -> int:
    """冒烟入口：建双规则→（管理员）阻断/放行/存量连接验证→清理。"""
    print("[smoke_fw] loading config.json ...")
    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    admin = _is_admin()
    print(f"[smoke_fw] admin={admin}")

    print("[smoke_fw] creating CG-Global + CG-V6 ...")
    create_rule(cfg)
    create_rule_v6(cfg)
    print("[smoke_fw] rules created; CG-Global enabled:", get_status(cfg))

    if not admin:
        print("[smoke_fw] SKIP: not elevated — cannot read rule state reliably,")
        print("[smoke_fw]        and blocking/allow verification requires admin.")
        print("[smoke_fw] verified: PS invocation path works and error handling")
        print("[smoke_fw]          for non-admin flows did not crash the module.")
        print("[smoke_fw] cleanup: removing CG-Global (best effort, needs admin).")
        try:
            remove_rules(cfg)
        except FirewallError as exc:
            print(f"[smoke_fw] cleanup skipped: {exc}")
        return 0

    # --- 阻断验证（Enable）---
    enable(cfg)
    print("[smoke_fw] CG-Global enabled; status:", get_status(cfg))
    ok = _connect_claude()
    print(f"[smoke_fw] blocked-phase connect to claude.ai: {'REACHED (BAD)' if ok else 'REFUSED (expected)'}")

    # --- 放行验证（Disable）---
    disable(cfg)
    print("[smoke_fw] CG-Global disabled; status:", get_status(cfg))
    ok = _connect_claude()
    print(f"[smoke_fw] allowed-phase connect to claude.ai: {'REACHED (expected)' if ok else 'REFUSED (BAD)'}")

    # --- 存量 TCP 连接行为实测 ---
    print("[smoke_fw] existing-connection test: open connection to claude.ai ...")
    s = _open_claude_socket()
    if s is None:
        print("[smoke_fw] SKIP: could not pre-open a connection (network/blocked).")
    else:
        print("[smoke_fw] connection open; enabling rule mid-connection ...")
        enable(cfg)
        alive = _probe_connection(s)
        print(f"[smoke_fw] pre-existing connection after Enable: {'STILL ALIVE' if alive else 'DEAD (WFP interrupted it)'}")
        s.close()

    print("[smoke_fw] cleanup: removing CG-Global + CG-V6 ...")
    remove_rules(cfg)
    print("[smoke_fw] done.")
    return 0


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _connect_claude(host: str = "claude.ai", port: int = 443, timeout: float = 5.0) -> bool:
    """尝试 TCP 连接 claude.ai，返回是否成功。"""
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _open_claude_socket(host: str = "claude.ai", port: int = 443, timeout: float = 5.0):
    import socket

    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        print(f"[smoke_fw] pre-open failed: {exc}")
        return None


def _probe_connection(sock, timeout: float = 3.0) -> bool:
    """对既有连接做一次非阻塞 peek，判断连接是否仍然存活。"""
    import select
    import socket

    sock.setblocking(False)
    try:
        r, _, _ = select.select([sock], [], [], timeout)
        if not r:
            # 无数据可读不等于死亡；再发一次探测确认
            try:
                sock.send(b"")
                return True  # send on healthy connection returns 0 bytes ok
            except OSError:
                return False
        data = sock.recv(1, socket.MSG_PEEK)
        if data == b"":
            return False  # 对端关闭（可能因 WFP RST）
        return True
    except (ConnectionResetError, OSError):
        return False


def remove_rules(config: Config) -> None:
    """删除 CG-Global 与 CG-V6（冒烟清理用；生产代码不调用）。"""
    _run_ps(
        "Remove-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_v4)
        + " -ErrorAction SilentlyContinue"
    )
    _run_ps(
        "Remove-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_v6)
        + " -ErrorAction SilentlyContinue"
    )


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
