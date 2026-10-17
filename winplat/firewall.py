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


class FirewallTimeoutError(FirewallError):
    """PowerShell 子进程超时（如冷启动超过时限）——与权限错误分开，
    超时不代表需要管理员权限，不应误导排障。"""


# 规则三态：Enabled / Disabled / 规则不存在（被第三方删除等）
class RuleStatus(str):
    """规则状态字符串。真值即“Enabled”，可直接用于 bool() 判断，
    便于既有调用方 `bool(get_status(...))` 无缝兼容三态语义。"""

    def __bool__(self) -> bool:
        return self == "ENABLED"


STATUS_ENABLED = RuleStatus("ENABLED")
STATUS_DISABLED = RuleStatus("DISABLED")
STATUS_MISSING = RuleStatus("MISSING")


class RuleNotFoundError(FirewallError):
    """查询的规则不存在。"""


def _ps_quote(value: str) -> str:
    """把参数安全嵌入 PowerShell 单引号字符串（单引号翻倍转义）。"""
    return "'" + value.replace("'", "''") + "'"
def _ps_array(values: list[str]) -> str:
    """把 CIDR 列表编码为 PowerShell 数组字面量（逗号拼接的 IPv6 CIDR 列表会被
    NetSecurity 判为非法地址——已实测；数组语法 v4/v6 均通过）。"""
    return "@(" + ",".join(_ps_quote(v) for v in values) + ")"


def _run_ps(script: str) -> str:
    """执行一段 PowerShell 脚本，返回 stdout。权限/超时错误有明确异常。

    CREATE_NO_WINDOW：GUI 进程（托盘 exe 无控制台）spawn 控制台子进程时
    默认会闪出黑窗，干扰用户——必须抑制。"""
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_PS_TIMEOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        # 超时≠权限问题：PS 冷启动可能超过 10s（非管理员），也可能是系统
        # 卡顿。归入独立超时异常，避免误报“需要管理员”误导排障。
        raise FirewallTimeoutError(
            f"PowerShell timed out after {_PS_TIMEOUT}s"
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
    remote = _ps_array(config.blocked_cidrs_v4)
    script = (
        f"$existing = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        f"if ($existing) {{ Remove-NetFirewallRule -DisplayName {name} -ErrorAction Stop }}; "
        "New-NetFirewallRule -DisplayName " + name
        + " -Direction Outbound -Action Block -Enabled True"
        + " -RemoteAddress " + remote  # 不指定协议 = Any：同时封 TCP 与 UDP/QUIC
        + " | Out-Null"
    )
    _run_ps(script)


def enable(config: Config) -> None:
    """启用 CG-Global（阻断态）。Enable 后复查实际状态，不符则抛错
    （防止对不存在规则 enable 时 cmdlet exit 0 的假成功）。"""
    _run_ps(
        "Enable-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_v4)
    )
    if get_status(config) != STATUS_ENABLED:
        raise FirewallError(
            f"Enable-NetFirewallRule returned success but rule "
            f"{config.rule_name_v4!r} is not Enabled (possibly deleted)"
        )


def disable(config: Config) -> None:
    """停用 CG-Global（放行态）。仅门禁逻辑允许调用。

    幂等：规则不存在（MISSING）视为已放行，直接成功——规则不在 = 无
    阻断可停，重试毫无意义（曾 3 次重试 + 1.5s 睡眠白拖 4s）。"""
    if get_status(config) == STATUS_MISSING:
        return
    _run_ps(
        "Disable-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_v4)
    )


def set_blocking(config: Config, blocking: bool) -> None:
    """批量切换 CG-Global + CG-FakeIP 到阻断/放行态（命令路径专用）。

    单次 PS 进程完成"切换+复查"：数组参数同时操作两条规则（cmdlet 只调
    一次），复查用数组 Get（同进程第二次 cmdlet 复用 CIM 会话）。实测
    （[耗时] 排查日志）：两次独立调用 ~7.7s（每进程付 ~2.5s NetSecurity
    加载税 ×2）→ 单进程数组 ~3.6-4.0s。注意：-PassThru 返回切换前快照
    不能当复查依据（实测 Disable 后 .Enabled 仍 True）。

    动词不带 -ErrorAction Stop（P1-3）：数组中缺失的 DisplayName 只产生
    非终止错误，cmdlet 继续处理其余名——CG-FakeIP 不存在（Clash 未运行/
    采集为空）时整脚本仍成功，缺失判定交给复查层。带 Stop 时缺失名把
    非终止错误升级为脚本失败，`_run_ps` 抛 FirewallError，disable 的
    "规则不存在=已放行"幂等分支被前置短路永不可达。

    复查按方向收紧：
    - blocking=True：CG-Global 必须存在且 Enabled（states 首位，Enable
      按数组顺序操作）；CG-FakeIP 缺失可接受（无 fake-ip 集合时本就
      不存在，heal 线程 ensure_exists 重建兜底）。
    - blocking=False：所有实际存在的规则均 False 即成功；states 为空
      （两条都不存在）= 幂等成功。
    动词对不存在规则 exit 0 假成功——不能只看 _run_ps 不抛，必须逐值
    比对 states（AGENTS.md 已录坑）。
    """
    n1 = _ps_quote(config.rule_name_v4)
    n2 = _ps_quote(config.rule_name_fakeip)
    verb = "Enable" if blocking else "Disable"
    want = "True" if blocking else "False"
    script = (
        "Import-Module NetSecurity;"
        f"{verb}-NetFirewallRule -DisplayName @({n1},{n2});"
        f"(Get-NetFirewallRule -DisplayName @({n1},{n2})"
        " -ErrorAction SilentlyContinue)"
        " | ForEach-Object { Write-Output ([string]$_.Enabled) }"
    )
    out = _run_ps(script)
    states = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if not blocking:
        # disable：所有实际存在的规则都已 False 即成功；
        # states 为空 = 两条都不存在 = 幂等成功。
        for s in states:
            if s != want:
                raise FirewallError(
                    f"set_blocking(False) verification failed: {states!r}"
                )
        return
    # enable：CG-Global（首位）必须存在且 Enabled；CG-FakeIP 缺失可接受。
    if not states or states[0] != want:
        raise FirewallError(
            f"set_blocking(True) CG-Global not enabled: states={states!r}"
        )
    for s in states[1:]:
        if s != want:
            raise FirewallError(
                f"set_blocking(True) verification failed: {states!r}"
            )

def block_all(config: Config, fakeip_ips: list[str] | None = None) -> None:
    """退出路径专用：一个 PS 进程确保 CG-Global + CG-FakeIP 都 Enabled。

    原退出路径 4 次串行 PS 调用（ensure_exists→enable→ensure_exists_fakeip
    →enable_fakeip）实测 ~15.6s（每次进程付 ~2.5s NetSecurity 加载税，
    [耗时] 日志证据）。本函数单进程完成"缺失重建 + 启用 + 数组复查"。
    CG-V6 不在本函数职责内：它由 heal 线程 ensure_enabled_v6 常驻保障
    （永久阻断，退出语义不改变它）。
    fakeip_ips=None/空 → CG-FakeIP 不存在则跳过（无 fake-ip 集合时
    重建无意义，与原路径 if self._fakeip_rule_ips 一致）。
    """
    n1 = _ps_quote(config.rule_name_v4)
    n2 = _ps_quote(config.rule_name_fakeip)
    remote1 = _ps_array(list(config.blocked_cidrs_v4))
    fakeip_part = ""
    if fakeip_ips:
        remote2 = _ps_array(list(fakeip_ips))
        fakeip_part = (
            f"$r2 = Get-NetFirewallRule -DisplayName {n2} -ErrorAction SilentlyContinue; "
            f"if (-not $r2) {{ Remove-NetFirewallRule -DisplayName {n2} "
            "-ErrorAction SilentlyContinue; "
            "New-NetFirewallRule -DisplayName " + n2
            + " -Direction Outbound -Action Block -Enabled True"
            + " -RemoteAddress " + remote2 + " | Out-Null; }; "
            f"Enable-NetFirewallRule -DisplayName {n2} -ErrorAction Stop; "
        )
    script = (
        "Import-Module NetSecurity; "
        f"$r1 = Get-NetFirewallRule -DisplayName {n1} -ErrorAction SilentlyContinue; "
        f"if (-not $r1) {{ Remove-NetFirewallRule -DisplayName {n1} "
        "-ErrorAction SilentlyContinue; "
        "New-NetFirewallRule -DisplayName " + n1
        + " -Direction Outbound -Action Block -Enabled True"
        + " -RemoteAddress " + remote1 + " | Out-Null; }; "
        f"Enable-NetFirewallRule -DisplayName {n1} -ErrorAction Stop; "
        + fakeip_part
        + f"(Get-NetFirewallRule -DisplayName @({n1},{n2})"
        " -ErrorAction SilentlyContinue)"
        " | ForEach-Object { Write-Output ([string]$_.Enabled) }"
    )
    out = _run_ps(script)
    states = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    # 复查：查到的规则必须全部 Enabled 且至少 1 条（CG-Global）。
    # fakeip_ips 为空时 CG-FakeIP 可能不存在（输出 1 行）——但若它
    # 恰好存在（守护期间创建过）也不能算失败：Enable 阶段已带
    # -ErrorAction Stop，存在即已被强制启用，2 行 True 同样合法。
    # （首版按 expected 严格行数比对，CG-FakeIP 存在时恒误判失败。）
    if not states or any(s != "True" for s in states):
        raise FirewallError(
            f"block_all verification failed: {states!r} out={out!r}")


def _build_get_status_script(name: str) -> str:
    """构造查询规则状态的 PS 脚本（纯函数，可离线单测）。name 需先经 _ps_quote。"""
    return (
        f"$r = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        "if ($r) { $r.Enabled } "
        "else { Write-Output 'MISSING' }"
    )


def _parse_get_status_output(out: str) -> RuleStatus:
    """解析 get_status 的 PS stdout（纯函数，可离线单测）。

    期望输出：'True' / 'False' / 'MISSING'。空输出或乱码按 MISSING 处理
    （下一轮自愈 ensure_exists 会重建），绝不猜成 Enabled。
    """
    out = (out or "").strip()
    if out.lower() == "true":
        return STATUS_ENABLED
    if out.lower() == "false":
        return STATUS_DISABLED
    return STATUS_MISSING


def get_status(config: Config) -> RuleStatus:
    """返回 CG-Global 三态（ENABLED/DISABLED/MISSING）。规则不存在不抛异常。

    返回值为 RuleStatus(str)：bool() 语义 = 是否 Enabled，
    兼容旧调用方 `bool(get_status(...))`。
    """
    out = _run_ps(_build_get_status_script(_ps_quote(config.rule_name_v4)))
    return _parse_get_status_output(out)


def ensure_exists(config: Config) -> None:
    """确保 CG-Global 存在；MISSING → 重建（重建后为 Enabled），DISABLED/ENABLED 不动作。"""
    script = (
        f"$r = Get-NetFirewallRule -DisplayName {_ps_quote(config.rule_name_v4)} "
        "-ErrorAction SilentlyContinue; "
        "if (-not $r) { Write-Output 'REBUILD' } else { Write-Output 'OK' }"
    )
    if _run_ps(script) == "REBUILD":
        create_rule(config)


# ------------------------------------------------------------------- CG-V6

def create_rule_v6(config: Config) -> None:
    """创建（或覆盖重建）CG-V6 规则，永久阻断 blocked_cidrs_v6。"""
    name = _ps_quote(config.rule_name_v6)
    remote = _ps_array(config.blocked_cidrs_v6)
    script = (
        f"$existing = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        f"if ($existing) {{ Remove-NetFirewallRule -DisplayName {name} -ErrorAction Stop }}; "
        "New-NetFirewallRule -DisplayName " + name
        + " -Direction Outbound -Action Block -Enabled True"
        + " -RemoteAddress " + remote  # 不指定协议 = Any：同时封 TCP 与 UDP/QUIC
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


# ---------------------------------------------------------------- CG-FakeIP

def create_rule_fakeip(config: Config, ips) -> None:
    """创建（或覆盖重建）CG-FakeIP 规则，阻断 claude_domains 当前解析到的
    fake-ip 集合。Any 协议（C4）：同时封 TCP 与 UDP/QUIC。"""
    name = _ps_quote(config.rule_name_fakeip)
    remote = _ps_array(list(ips))
    script = (
        f"$existing = Get-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; "
        f"if ($existing) {{ Remove-NetFirewallRule -DisplayName {name} -ErrorAction Stop }}; "
        "New-NetFirewallRule -DisplayName " + name
        + " -Direction Outbound -Action Block -Enabled True"
        + " -RemoteAddress " + remote
        + " | Out-Null"
    )
    _run_ps(script)


def enable_fakeip(config: Config) -> None:
    """启用 CG-FakeIP（阻断态）。Enable 后复查实际状态，不符则抛错。"""
    _run_ps(
        "Enable-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_fakeip)
    )
    if get_status_fakeip(config) != STATUS_ENABLED:
        raise FirewallError(
            f"Enable-NetFirewallRule returned success but rule "
            f"{config.rule_name_fakeip!r} is not Enabled (possibly deleted)"
        )


def disable_fakeip(config: Config) -> None:
    """停用 CG-FakeIP（放行态）。仅门禁逻辑允许调用。

    幂等：规则不存在视为已放行（与 disable 同理）。"""
    if get_status_fakeip(config) == STATUS_MISSING:
        return
    _run_ps(
        "Disable-NetFirewallRule -DisplayName "
        + _ps_quote(config.rule_name_fakeip)
    )


def get_status_fakeip(config: Config) -> RuleStatus:
    """返回 CG-FakeIP 三态（ENABLED/DISABLED/MISSING）。规则不存在不抛异常。"""
    out = _run_ps(_build_get_status_script(_ps_quote(config.rule_name_fakeip)))
    return _parse_get_status_output(out)


def ensure_exists_fakeip(config: Config, ips) -> None:
    """确保 CG-FakeIP 存在；MISSING → 用 ips 重建（重建后为 Enabled），
    DISABLED/ENABLED 不动作。"""
    script = (
        f"$r = Get-NetFirewallRule -DisplayName {_ps_quote(config.rule_name_fakeip)} "
        "-ErrorAction SilentlyContinue; "
        "if (-not $r) { Write-Output 'REBUILD' } else { Write-Output 'OK' }"
    )
    if _run_ps(script) == "REBUILD":
        create_rule_fakeip(config, ips)


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
    # CG-FakeIP 一并清理（冒烟产物；不存在时 SilentlyContinue）
    fakeip_name = getattr(config, "rule_name_fakeip", None)
    if fakeip_name:
        _run_ps(
            "Remove-NetFirewallRule -DisplayName "
            + _ps_quote(fakeip_name)
            + " -ErrorAction SilentlyContinue"
        )


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
