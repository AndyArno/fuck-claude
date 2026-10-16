# -*- coding: utf-8 -*-
"""Claude Guard 主循环（组装层）— docs/02-architecture.md §2.4。

单线程轮转调度：
- 主循环按 fast_tick_sec（默认 1s）轮转，每轮必查快路径（psutil 本地检查），
  每 N = slow_tick_sec / fast_tick_sec 轮查一次慢路径（echo + fake-ip）。
- 漂移监控（DoH / RIPE）为独立守护线程，只投递 DRIFT_DETECTED 事件，不动规则。
- 每轮做规则自愈：CG-Global 实际状态与状态机期望不一致时纠正（防第三方重置）；
  CG-V6 每轮 ensure_enabled_v6（永久封死，门禁无权放行）。
- override：OVERRIDE_START 起 override_minutes 计时，期间不阻断但记录审计日志，
  到期自动恢复检查（OVERRIDE_EXPIRE）。
- PAUSE/RESUME：暂停守护但不动规则（保持阻断态，只停检查）。
- QUIT：规则保持当前实际状态退出（fail-closed：阻断态退出即阻断）；
  EXIT：恢复 Enabled 后退出（需求 T-6）。
- config 热重载：定期 mtime 检查，白名单编辑后无需重启。

本模块不依赖托盘库：托盘只通过 duck-typed 的 Tray 抽象（push_event /
commands 队列）交互，可被 exe 入口（scripts/run_guardian.py）复用。

所有 platform 依赖均可注入（fw / np / dns / ripe / notify_fn），供单测 mock。
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import threading
import time
from pathlib import Path

from core import checks as core_checks
from core import messages
from core import policy
from core import statemachine as sm
from core.config import Config, ConfigError, load as load_config

# platform 层默认实现（测试时整体注入替身）
from winplat import dnscheck, firewall as fw_mod, netprobe, ripecheck

_LOGGER_NAME = "claude-guard"

# 内部事件队列里除状态机事件外还可放控制标记
_STOP = "__stop__"


def setup_logging(config: Config, logger: logging.Logger | None = None) -> logging.Logger:
    """按天滚动日志：logs/guard-YYYYMMDD.log，保留 log_retention_days 天。"""
    log = logger or logging.getLogger(_LOGGER_NAME)
    if log.handlers:  # 已初始化
        return log
    log.setLevel(logging.INFO)
    log_dir = Path(config.log_dir or "logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(log_dir / "guard.log"),
        when="midnight",
        backupCount=config.log_retention_days,
        encoding="utf-8",
    )
    # 滚动文件名 guard-YYYYMMDD.log（需求 P-4 / 架构 §6）
    handler.suffix = "%Y%m%d"
    handler.namer = _guard_namer
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s [%(threadName)s] %(message)s"))
    log.addHandler(handler)
    return log


def _guard_namer(default_name: str) -> str:
    """guard.log.20261015 -> guard-20261015.log"""
    base, _, stamp = default_name.rpartition(".")
    return f"guard-{stamp}.log"


def _default_notify(title: str, body: str) -> None:
    from winplat.notify import notify_state

    notify_state(title, body)


def collect_fakeips(config: Config, log: logging.Logger | None = None) -> tuple[str, ...]:
    """解析 config.claude_domains 全部域名（getaddrinfo），只收落在
    fakeip_range 内的地址，返回有序去重集合。解析失败/返回真实 IP 的地址
    不入集（真实 IP 由 CG-Global 覆盖，不得重复塞入 CG-FakeIP）。"""
    import ipaddress
    import socket

    log = log or logging.getLogger(_LOGGER_NAME)
    try:
        net = ipaddress.ip_network(config.fakeip_range)
    except ValueError as exc:
        log.warning("fakeip_range 非法，跳过 CG-FakeIP 采集：%s", exc)
        return ()
    found: list[str] = []
    for domain in config.claude_domains:
        try:
            infos = socket.getaddrinfo(domain, None)
        except OSError as exc:
            log.warning("fake-ip 解析 %s 失败（跳过该域名）：%s", domain, exc)
            continue
        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if ip.version == 4 and ip in net and str(ip) not in found:
                found.append(str(ip))
    return tuple(found)


class Guardian:
    """门禁主循环。单线程 tick；漂移线程只投事件；规则自愈在独立线程。"""

    def __init__(
        self,
        config: Config,
        config_path: str | os.PathLike = "config.json",
        *,
        fw=None,
        np=None,
        dns=None,
        ripe=None,
        notify_fn=None,
        tray=None,
        clock=time.monotonic,
        sleep_fn=time.sleep,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.config_path = str(config_path)
        self.fw = fw or fw_mod
        self.np = np or netprobe
        self.dns = dns or dnscheck
        self.ripe = ripe or ripecheck
        self._notify = notify_fn or _default_notify
        self.tray = tray
        self._clock = clock
        self._sleep = sleep_fn
        self.log = logger or logging.getLogger(_LOGGER_NAME)

        # 状态机状态（启动即阻断态，fail-closed）
        self._gstate = sm.GateState(state=sm.BLOCKED)
        self._counter = core_checks.CheckCounter(
            config.pass_confirm_count, config.fail_unreachable_threshold
        )
        self.paused = False
        self.override_until: float | None = None

        # 规则自愈（H1）：PS 子进程单次 ~1.6s，绝不能阻塞快路径 tick。
        # 自愈跑在独立线程：30s 周期；主循环状态迁移/动作后通过 Event 唤醒
        # 立即校验。_fw_lock 保证 heal 线程与主循环的防火墙调用不交错。
        self._heal_interval = 30.0
        self._fw_lock = threading.Lock()
        self._heal_wake = threading.Event()   # 主循环 → heal 线程：立即 heal
        self._heal_thread: threading.Thread | None = None
        # fake-ip 迁移刷新（时序残余修复）：状态迁移后立即重采集重建
        # CG-FakeIP，不等慢路径 5s。重采集有 getaddrinfo + PS 开销，
        # 也放独立线程（failip-refresh），绝不阻塞主循环快路径。
        self._fakeip_wake = threading.Event()  # 主循环 → refresh 线程：立即刷新
        self._fakeip_thread: threading.Thread | None = None

        self._tick_count = 0
        self._slow_every = max(
            1, round(config.slow_tick_sec / max(1, config.fast_tick_sec))
        )
        self._last_echo_ip: str | None = None
        self._last_echo_in_whitelist: bool | None = None
        self._last_dns_ip: str | None = None
        # CG-FakeIP：当前规则内的 fake-ip 集合（上次成功写入的内容）；
        # None = 尚未采集过。采集失败（空集）时规则保持上次内容，无害
        # （真实 IP 已由 CG-Global 覆盖）。
        self._fakeip_rule_ips: tuple[str, ...] | None = None
        self._last_checks: dict[str, str] = {}
        self._config_mtime: float | None = self._stat_mtime()
        self._stop = threading.Event()
        # 托盘命令唤醒：托盘投递命令时 set，主循环 _sleep 立即打断
        # （命令毫秒级处理，不等下轮 fast tick——override 延迟实测 ~7s→~2s）
        self._cmd_wake = threading.Event()
        self._incoming: queue.Queue = queue.Queue()
        self._drift_thread: threading.Thread | None = None
        self.exited = threading.Event()      # 主循环结束标志（入口感知退出）
        self._thread: threading.Thread | None = None
        # 审计日志（override）
        self._audit_path = Path(config.log_dir or "logs") / "override-audit.log"

    # ------------------------------------------------------------------ 生命周期

    def start(self) -> None:
        """启动漂移/自愈线程 + 主循环线程；先预热防火墙子进程。"""
        self._preheat()
        # 托盘命令 → 立即唤醒主循环（可中断睡眠）
        if self.tray is not None and hasattr(self.tray, "_on_command"):
            self.tray._on_command = self._cmd_wake.set
        self._drift_thread = threading.Thread(
            target=self._drift_loop, name="drift-monitor", daemon=True
        )
        self._drift_thread.start()
        self._heal_thread = threading.Thread(
            target=self._heal_loop, name="rule-heal", daemon=True
        )
        self._heal_thread.start()
        self._fakeip_thread = threading.Thread(
            target=self._fakeip_refresh_loop, name="fakeip-refresh", daemon=True
        )
        self._fakeip_thread.start()
        self._thread = threading.Thread(target=self.run, name="guardian-main", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        self._heal_wake.set()          # 唤醒 heal 线程令其检查退出标志
        self._incoming.put(_STOP)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._heal_thread is not None:
            self._heal_thread.join(timeout=3.0)
        self._fakeip_wake.set()
        if self._fakeip_thread is not None:
            self._fakeip_thread.join(timeout=3.0)
        if self._drift_thread is not None:
            self._drift_thread.join(timeout=2.0)

    def run(self) -> None:
        """主循环：每轮 tick + 睡 fast_tick；QUIT/EXIT 命令退出。"""
        self.log.info("Guardian 启动：fast=%ds slow=%ds（每 %d 轮）",
                      self.config.fast_tick_sec, self.config.slow_tick_sec,
                      self._slow_every)
        while not self._stop.is_set():
            try:
                if self.tick() is False:
                    break
            except Exception:
                self.log.exception("tick 异常（继续运行，fail-closed）")
            # 可中断睡眠：托盘命令到达（_cmd_wake.set）立即醒，否则睡满
            # fast_tick。命令延迟从 0~1s 降到毫秒级。
            self._cmd_wake.wait(self.config.fast_tick_sec)
            self._cmd_wake.clear()
        self.log.info("Guardian 主循环退出")
        self.exited.set()  # 通知入口：主循环已结束（不依赖 is_alive 轮询）
        # 托盘"退出"由 handle_command 完成 enable 后走到这里；被外部 stop()
        # 时同样成立。入口 finally 兜底 os._exit 保证进程死透。

    # ------------------------------------------------------------------ 单轮 tick

    def tick(self) -> bool:
        """执行一轮；返回 False 表示收到退出命令。"""
        self._tick_count += 1

        # ① 托盘命令（非阻塞 drain）
        if self._drain_commands() is False:
            return False

        # ② config 热重载（mtime 变化则重载白名单等）
        self._maybe_reload_config()

        # ③ 漂移线程投递的事件
        self._drain_incoming()

        # ③ 暂停守护：只停“检查”，不放弃已有安全职责——
        #   - override 到期判断照常（否则 override+暂停 = 无限期放行）
        #   - CG-V6 每轮强制 Enabled 照常（B-6 与暂停无关）
        #   - 规则冻结在阻断态（pause 命令处理时已 enable）
        if self.paused:
            if self._gstate.on_override and self.override_until is not None \
                    and self._clock() >= self.override_until:
                self._log_audit("end")
                self.log.info("Override 到期（暂停期间），恢复阻断")
                self.override_until = None
                self._counter.reset()
                self._apply_event(sm.OVERRIDE_EXPIRE)
            try:
                with self._fw_lock:
                    self.fw.ensure_enabled_v6(self.config)
            except Exception as exc:
                self.log.warning("暂停期间 CG-V6 ensure 失败：%s", exc)
            self._push_tray()
            return True

        # ④ override 到期
        if self._gstate.on_override and self.override_until is not None \
                and self._clock() >= self.override_until:
            self._log_audit("end")
            self.log.info("Override 到期，恢复检查")
            self.override_until = None
            self._counter.reset()
            self._apply_event(sm.OVERRIDE_EXPIRE)

        # ⑤ 快路径：mihomo 进程 + TUN 网卡（纯本地，<1ms）
        event: str | None = None
        local = self._safe_local_env()
        fast_ok = local.mihomo_running and local.tun_present
        if not fast_ok:
            event = sm.FAST_FAIL
            self._last_checks = {
                "mihomo进程": False, "TUN网卡": False,
                "fake-ip": None, "echo出口": None,
            }
        elif self._tick_count == 1 or self._tick_count % self._slow_every == 0:
            # ⑥ 慢路径：echo 出口 IP 三分法 + fake-ip 生效。
            # 第 1 轮即跑（不等第 5 轮）：启动→首检省 4 个 fast tick，
            # 配合确认窗口 3 轮慢路径，启动放行最快 ~15s→~11s，且托盘
            # 从第一秒就有真实检查数据（此前前 4 秒全是空白误报窗口）。
            event = self._slow_path(local)

        # ⑦ 转移 + 副作用
        if event is not None:
            self._apply_event(event)

        # ⑧ 规则自愈已移至独立后台线程（_heal_loop）：状态迁移/动作后由
        # _apply_event/_execute 通过 _heal_wake 触发立即校验。主循环从此
        # 不再被 PowerShell 子进程调用（~1.6s/次）阻塞，快路径检测间隔回到
        # fast_tick 级别（B-7：杀 mihomo → FAST_FAIL 发现 ≤1s）。

        # ⑨ 通知 UI
        self._push_tray()
        return True

    # ---------------------------------------------------------- CG-FakeIP

    def _collect_fakeips(self) -> tuple[str, ...]:
        """解析 config.claude_domains 全部域名，只收 fakeip_range 内的地址。"""
        return collect_fakeips(self.config, self.log)

    def _refresh_fakeip_rule(self) -> None:
        """慢路径每轮调用：重解析 fake-ip 集合，变化时重建 CG-FakeIP。

        fake-ip 映射会因 mihomo 重启/缓存淘汰变化（RemoteAddress 只在
        create 时写入，必须重建规则）。采集为空（Clash 死了，getaddrinfo
        返回真实 IP 或失败）→ 保持规则现状：真实 IP 已由 CG-Global 覆盖。"""
        ips = self._collect_fakeips()
        if ips == self._fakeip_rule_ips:
            return
        if not ips:
            self.log.info("fake-ip 集合为空，CG-FakeIP 保持现状")
            return
        if self._fw_tolerant("create_rule_fakeip", list(ips)):
            self._fakeip_rule_ips = ips
            # create 后规则默认 Enabled；放行态下须恢复 Disabled
            if self._gstate.state == sm.ALLOWED or self._gstate.on_override:
                self._fw_tolerant("disable_fakeip")
            self.log.info("CG-FakeIP 已更新（%d 个 fake-ip）", len(ips))

    # ------------------------------------------------------------------ 检查路径

    def _safe_local_env(self):
        try:
            return self.np.check_local_env(self.config)
        except Exception as exc:
            self.log.warning("本地环境检查失败：%s", exc)
            return netprobe.LocalEnvResult(
                mihomo_running=False, tun_present=False, error=str(exc))

    def _slow_path(self, local) -> str | None:
        """慢路径一轮，返回状态机事件或 None（无事件）。"""
        # CG-FakeIP：每轮慢路径重解析 fake-ip 集合，变化即重建（不阻塞判定：
        # 重建失败由 _fw_tolerant 容错，下轮自愈再纠正）。
        try:
            self._refresh_fakeip_rule()
        except Exception as exc:
            self.log.warning("CG-FakeIP 刷新失败（保持现状）：%s", exc)
        fakeip_ok = self._check_fakeip()
        echo = self._probe_echo()
        verdict_before = policy.classify(echo.ip if echo.ok else None,
                                         list(self.config.whitelist))
        self._last_echo_ip = echo.ip if echo.ok else self._last_echo_ip
        # ⑤ DNS 出口探针：递归出口 IP 不在白名单与出口脏同权（立即阻断）；
        # akahelp 不可达则 UNREACHABLE，计入现有不可达计数。
        dns_verdict, dns_probe = self._probe_dns_egress()
        # 综合：任一 DIRTY 即 DIRTY（立即阻断）；两者都 CLEAN 才算 CLEAN；
        # 否则（echo 或 DNS 不可达）走 UNREACHABLE 计数语义。
        if policy.DIRTY in (verdict_before, dns_verdict):
            verdict = policy.DIRTY
        elif verdict_before == policy.CLEAN and dns_verdict == policy.CLEAN:
            verdict = policy.CLEAN
        else:
            verdict = policy.UNREACHABLE
        self._last_dns_ip = dns_probe.egress_ip
        self._last_echo_in_whitelist = (
            verdict_before == policy.CLEAN if echo.ok else None)
        self._last_checks = {
            "mihomo进程": bool(local.mihomo_running),
            "TUN网卡": bool(local.tun_present),
            "fake-ip": bool(fakeip_ok),
            "echo出口": bool(echo.ok),
            "DNS出口干净": dns_verdict == policy.CLEAN,
        }
        self.log.info(
            "慢路径：echo=%s fakeip=%s dns=%s verdict=%s",
            echo.ip if echo.ok else f"不可达({echo.error})",
            fakeip_ok,
            (dns_probe.egress_ip if dns_probe.ok
             else f"不可达({dns_probe.error})"),
            verdict,
        )

        result = core_checks.evaluate(
            {
                "mihomo_alive": local.mihomo_running,
                "tun_present": local.tun_present,
                "fakeip_ok": fakeip_ok,
            },
            verdict,
            self._counter,
        )
        if result == "BLOCK_NOW":
            return sm.CHECK_FAIL
        if result == "PASS_CONFIRMED":
            return sm.CHECK_PASS
        # HOLD：不可达时按 counter 升级语义保留 UNREACHABLE 事件；其余无事件
        if verdict == policy.UNREACHABLE:
            return sm.PROBE_UNREACHABLE
        return None

    def _probe_dns_egress(self):
        """检查⑤：whoami TXT 探针，返回 (verdict, DnsEgressResult)。"""
        try:
            return self.dns.check_dns_egress(
                self.config.dns_probe_domain, self.dns_whitelist)
        except Exception as exc:
            self.log.warning("DNS 出口探针异常：%s", exc)
            return policy.UNREACHABLE, dnscheck.DnsEgressResult(
                ok=False, error=str(exc))

    @property
    def dns_whitelist(self) -> list[str]:
        """DNS 出口白名单：dns_whitelist 优先，缺省复用 echo 出口 whitelist。"""
        return list(self.config.dns_whitelist or self.config.whitelist)

    def _check_fakeip(self) -> bool:
        try:
            result = self.dns.check_fakeip(
                self.config.claude_domains[0], self.config.fakeip_range)
            return result.ok and result.in_fakeip_range
        except Exception as exc:
            self.log.warning("fake-ip 检查失败：%s", exc)
            return False

    def _probe_echo(self):
        try:
            return self.np.probe_echo_endpoints(list(self.config.echo_endpoints))
        except Exception as exc:
            self.log.warning("echo 探测异常：%s", exc)
            return netprobe.EchoResult(ok=False, ip=None, endpoint=None, error=str(exc))

    # ------------------------------------------------------------------ 状态机

    def _apply_event(self, event: str) -> None:
        old = self._gstate
        tr = sm.transition(self._gstate, event)
        self._gstate = tr.new_state
        if tr.actions:
            self._execute(tr.actions)
        if old != self._gstate or tr.actions:
            self.log.info("状态转移 %s --%s--> %s actions=%s",
                          old.state, event, self._gstate.state,
                          [a["action"] for a in tr.actions])
        # 状态迁移或动作发出后由 heal 线程立即校验规则实际状态（见下方 _heal_wake）
        if tr.actions or old != self._gstate:
            # 状态迁移/动作后触发 heal 线程立即校验规则实际状态（不阻塞主循环）。
            # 迁移点的 enable/disable 已是权威写入，本次校验是防线不是主路径；
            # 若 heal 线程正在跑一轮，事件不排队、合并成"结束后尽早再跑一轮"。
            self._heal_wake.set()
            # fake-ip 迁移刷新：迁移点立即重采集重建 CG-FakeIP。Clash 重启后
            # fake-ip 重分配，访问可能落在"新 fake-ip 生效、规则未重建"的
            # 慢路径 5s 间隙——迁移后首轮必须立即把新集合写进规则。
            self._fakeip_wake.set()

    def _execute(self, actions: list[dict]) -> None:
        for a in actions:
            act = a.get("action")
            if act == sm.ENABLE_FIREWALL:
                self._fw_tolerant("enable")
                # CG-FakeIP 与 CG-Global 同命运（门控规则，非永久规则）
                self._fw_tolerant("enable_fakeip")
            elif act == sm.DISABLE_FIREWALL:
                self._fw_tolerant("disable")
                self._fw_tolerant("disable_fakeip")
            elif act in (sm.NOTIFY_BLOCK, sm.NOTIFY_ALLOW, sm.NOTIFY_ALERT):
                title, body = self._toast_text(act)
                self._notify(title, body)
            else:  # pragma: no cover - 状态机之外的指令
                self.log.warning("未知 action: %r", a)

    def _toast_text(self, act: str) -> tuple[str, str]:
        """状态切换 Toast 文案，统一从 core.messages 取（用户可见面）。"""
        if act == sm.NOTIFY_ALLOW:
            # 临时放行开始的放行动作 ≠ 出口干净：override 语境用专属文案
            # （曾误报"出口 IP 干净"误导用户，实测发现）。
            if self._gstate.on_override:
                return messages.toast_override_start(self.config.override_minutes)
            return messages.toast_allow()
        if act == sm.NOTIFY_ALERT:
            return messages.toast_drift()
        # NOTIFY_BLOCK：拦截态附大白话原因。
        # 排除法：快/慢检查里 proxy/tunnel/dns 任一失败即按该项解释；
        # 否则若看到了出口 IP，说明 CHECK_FAIL 由“出口不在白名单”触发；
        # 否则若 DNS 出口探针看到白名单外 IP，按“DNS 泄漏”解释（检查⑤）。
        local = self._last_checks
        seen_ip = self._last_echo_ip is not None
        dns_leak = (local.get("DNS出口干净") is False
                    and self._last_dns_ip is not None)
        base = dict(
            blocking=True,
            proxy_ok=local.get("mihomo进程"),
            tunnel_ok=local.get("TUN网卡"),
            dns_ok=local.get("fake-ip"),
        )
        # 出口 IP 判脏优先于 DNS 泄漏（都脏时按出口解释）；仅 DNS 泄漏时按⑤解释
        echo_dirty = seen_ip and self._last_echo_in_whitelist is False
        if dns_leak and not echo_dirty:
            return messages.toast_block(
                messages.Status(dns_leak_ip=self._last_dns_ip, **base))
        s = messages.Status(
            probe_ok=False if local.get("echo出口") is False else (None if not seen_ip else True),
            exit_ip=self._last_echo_ip,
            in_whitelist=False if seen_ip else None,
            **base,
        )
        return messages.toast_block(s)

    # ------------------------------------------------------------------ 防火墙容错

    def _fw_tolerant(self, method: str, *args, retries: int = 3,
                     delay: float = 0.5, **kwargs) -> bool:
        """防火墙调用包裹重试/容错：PS 冷启动可达 13s（> firewall.py 10s 超时），
        失败重试；永不向上抛（主循环必须继续，fail-closed 下次自愈再纠正）。
        额外位置/关键字参数透传目标方法（如 create_rule_fakeip 的 ips）。
        单次调用整体持 _fw_lock：与 heal 线程的调用按次互斥，规则读写不交错
        （重试等待与子进程执行期间不持锁，锁粒度=一次 PS 调用）。"""
        for attempt in range(1, retries + 1):
            with self._fw_lock:
                try:
                    getattr(self.fw, method)(self.config, *args, **kwargs)
                    return True
                except Exception as exc:
                    self.log.error("防火墙 %s 第 %d/%d 次失败：%s",
                                   method, attempt, retries, exc)
            if attempt < retries:
                self._sleep(delay)
        self.log.error("防火墙 %s 重试 %d 次均失败（下轮自愈再纠正）", method, retries)
        return False

    def _preheat(self) -> None:
        """启动预热：触发一次 PowerShell 冷启动，避免首轮检查超时误判。"""
        try:
            with self._fw_lock:
                self.fw.ensure_exists(self.config)
            self.log.info("防火墙预热完成（CG-Global ensure_exists）")
        except Exception as exc:
            self.log.error("防火墙预热失败（将继续，由自愈兜底）：%s", exc)
        try:
            with self._fw_lock:
                self.fw.ensure_enabled_v6(self.config)
        except Exception as exc:
            self.log.error("CG-V6 预热失败：%s", exc)
        # CG-FakeIP 预热：采集初始 fake-ip 集合并创建规则。失败不阻断启动
        # （慢路径每轮重试；真实 IP 由 CG-Global 覆盖）。
        try:
            ips = self._collect_fakeips()
            if ips:
                with self._fw_lock:
                    self.fw.create_rule_fakeip(self.config, list(ips))
                self._fakeip_rule_ips = ips
                self.log.info("CG-FakeIP 预热完成（%d 个 fake-ip）", len(ips))
        except Exception as exc:
            self.log.error("CG-FakeIP 预热失败（将继续，由慢路径重试）：%s", exc)

    # ------------------------------------------------------------------ 规则自愈（后台线程）

    def _heal_loop(self) -> None:
        """规则自愈线程：默认每 heal_interval 秒一轮；主循环状态迁移/动作后
        通过 _heal_wake 唤醒立即校验。绝不让主循环等待 PowerShell。

        自愈异常不杀死线程（fail-closed 依赖规则校验兜底）——1s 后立即重试，
        等价旧实现 _last_heal=-inf 的"下轮重试"节奏。线程整体 try/except 续命。"""
        while not self._stop.is_set():
            delay = self._heal_interval
            try:
                self._self_heal_rules()
            except Exception as exc:
                self.log.warning("自愈异常，1s 后重试：%s", exc)
                delay = 1.0
            # 周期等待；主循环迁移触发 set _heal_wake → 提前唤醒立即校验
            if self._heal_wake.wait(timeout=delay):
                self._heal_wake.clear()

    def _fakeip_refresh_loop(self) -> None:
        """fake-ip 刷新线程：平时随慢路径节奏（_slow_path 每轮已调用
        _refresh_fakeip_rule）；状态迁移时被 _fakeip_wake 唤醒立即重采集
        重建 CG-FakeIP。阻塞型迁移场景（如暂停/恢复期间无慢路径）也由本
        线程兜底。异常续命，永不退出（除 stop）。"""
        while not self._stop.is_set():
            if self._fakeip_wake.wait():
                self._fakeip_wake.clear()
            if self._stop.is_set():
                return
            try:
                self._refresh_fakeip_rule()
            except Exception as exc:
                self.log.warning("迁移后 fake-ip 刷新失败（慢路径重试）：%s", exc)

    def _self_heal_rules(self) -> None:
        """校验 CG-Global 实际状态与状态机期望一致；CG-V6 永久封死。

        运行在独立 heal 线程（_heal_loop），不阻塞主循环快路径。所有
        PowerShell 调用持 _fw_lock，与主循环的 enable/disable 按次互斥。
        get_status / ensure_enabled_v6 为只读/幂等校验，裸调用后整体关闭，
        保证读取与写入的规则状态一致。"""
        expected_enabled = not (
            self._gstate.state == sm.ALLOWED or self._gstate.on_override
        )
        try:
            with self._fw_lock:
                actual = self.fw.get_status(self.config)
        except Exception as exc:
            self.log.warning("读取 CG-Global 状态失败（跳过本轮自愈）：%s", exc)
            return
        # 兼容两种语义：旧 bool（True/False）与新三态字符串
        # （'ENABLED'/'DISABLED'/'MISSING'）。MISSING → 重建。
        actual_str = str(actual).upper() if isinstance(actual, str) else None
        if actual_str == "MISSING":
            self.log.warning("CG-Global 规则缺失（可能被第三方删除），重建中")
            if self._fw_tolerant("ensure_exists"):
                # 重建后按期望状态恢复（create_rule 默认 Enabled）
                if not expected_enabled:
                    self._fw_tolerant("disable")
            return
        actual_enabled = actual_str == "ENABLED" if actual_str else bool(actual)
        if actual_enabled != expected_enabled:
            self.log.warning(
                "CG-Global 实际状态 %s 与期望 %s 不符（可能被第三方重置），纠正中",
                "Enabled" if actual_enabled else "Disabled",
                "Enabled" if expected_enabled else "Disabled",
            )
            self._fw_tolerant("enable" if expected_enabled else "disable")
        self._heal_fakeip(expected_enabled)
        try:
            with self._fw_lock:
                self.fw.ensure_enabled_v6(self.config)
        except Exception as exc:
            self.log.warning("CG-V6 ensure 失败：%s", exc)

    def _heal_fakeip(self, expected_enabled: bool) -> None:
        """CG-FakeIP 自愈：状态与期望不符则纠正；规则缺失且有已知集合则重建。
        无已知集合（从未采集成功）时跳过——真实 IP 已由 CG-Global 覆盖。"""
        try:
            with self._fw_lock:
                status = self.fw.get_status_fakeip(self.config)
        except Exception as exc:
            self.log.warning("读取 CG-FakeIP 状态失败（跳过本轮）：%s", exc)
            return
        status_str = str(status).upper()
        if status_str == "MISSING":
            if self._fakeip_rule_ips:
                self.log.warning("CG-FakeIP 规则缺失，用已知集合重建中")
                if self._fw_tolerant("ensure_exists_fakeip",
                                     list(self._fakeip_rule_ips)):
                    if not expected_enabled:
                        self._fw_tolerant("disable_fakeip")
            return
        # 与 CG-Global 相同的兼容语义：三态字符串优先，否则按 bool（真值=Enabled）
        actual_enabled = (status_str == "ENABLED" if status_str in
                          ("ENABLED", "DISABLED") else bool(status))
        if actual_enabled != expected_enabled:
            self.log.warning(
                "CG-FakeIP 实际状态 %s 与期望 %s 不符，纠正中",
                "Enabled" if actual_enabled else "Disabled",
                "Enabled" if expected_enabled else "Disabled",
            )
            self._fw_tolerant(
                "enable_fakeip" if expected_enabled else "disable_fakeip")

    # ------------------------------------------------------------------ 托盘命令

    def _drain_commands(self) -> bool:
        """处理托盘命令队列；返回 False 表示退出。

        命令处理完立即推送托盘状态：菜单✔/临时放行项的更新不等 tick
        末尾的统一推送（点击后最快路径反映，实测"跟手"的关键）。"""
        if self.tray is None:
            return True
        while True:
            try:
                cmd = self.tray.commands.get_nowait()
            except queue.Empty:
                return True
            value = cmd.value if hasattr(cmd, "value") else str(cmd)
            if self.handle_command(value) is False:
                return False
            self._push_tray()

    def handle_command(self, cmd: str) -> bool:
        """处理一条菜单命令；返回 False 表示退出主循环。"""
        cmd = str(cmd).strip().lower()
        if cmd == "override_30min":
            self._start_override()
        elif cmd == "end_override":
            # 手动立即结束临时放行：与自然到期同路径（fail-closed 恢复阻断）
            if self._gstate.on_override:
                self.override_until = None
                self._counter.reset()
                self._log_audit("end manual")
                self._apply_event(sm.OVERRIDE_EXPIRE)
                self.log.info("手动结束 Override：立即恢复阻断")
        elif cmd in ("toggle_pause", "pause", "resume"):
            # 合并后的菜单单项（✔=已暂停，点击切换）；pause/resume 兼容旧值
            if cmd == "toggle_pause":
                want_pause = not self.paused
            elif cmd == "pause":
                want_pause = True
            else:  # resume
                want_pause = False
            if want_pause and not self.paused:
                self.paused = True
                self._counter.reset()
                # 暂停语义 = 冻结在阻断态（fail-closed，安全优先）：
                # 强制 enable 规则，即使暂停前处于放行态/override。
                self._fw_tolerant("enable")
                self._fw_tolerant("enable_fakeip")
                self._gstate = sm.GateState(
                    sm.BLOCKED, self._gstate.drift_alarm, self._gstate.on_override)
                self.log.info("守护已暂停（规则冻结在阻断态，不执行检查）")
                self._notify(*messages.toast_paused())
            elif not want_pause and self.paused:
                self.paused = False
                self._counter.reset()
                self.log.info("守护已恢复")
                self._notify(*messages.toast_resumed())
        elif cmd == "edit_whitelist":
            self._open_whitelist_editor()
        elif cmd == "show_details":
            pass  # 详情气泡由托盘线程自己展示
        elif cmd == "quit":
            # fail-closed：规则保持当前实际状态退出（阻断态退出即阻断）
            self.log.info("收到退出命令（规则保持当前实际状态）")
            self._stop.set()
            return False
        elif cmd == "exit":
            # 需求 T-6：恢复 Enabled（阻断）后退出。
            # 先 ensure_exists 再 enable：规则若已被第三方删除，仅 enable 会
            # 3 次重试全抛错后裸退（复审 H4 边缘缺口）——必须重建再启用。
            self.log.info("收到 EXIT 命令：恢复阻断后退出")
            self._fw_tolerant("ensure_exists")
            self._fw_tolerant("enable")
            if self._fakeip_rule_ips:
                self._fw_tolerant("ensure_exists_fakeip",
                                  list(self._fakeip_rule_ips))
            self._fw_tolerant("enable_fakeip")
            self._stop.set()
            return False
        else:
            self.log.warning("未知命令：%r", cmd)
        return True

    def _start_override(self) -> None:
        if self._gstate.on_override:
            self.log.info("Override 已在进行中，忽略重复请求")
            return
        # 先设计时再施加副作用：若 _apply_event 中途异常，到期判定仍能恢复
        self.override_until = self._clock() + self.config.override_minutes * 60
        self._apply_event(sm.OVERRIDE_START)
        self._counter.reset()
        self._log_audit(
            f"start duration_min={self.config.override_minutes}")
        self.log.info("Override 开始：%d 分钟（期间不阻断，审计已记录）",
                      self.config.override_minutes)

    def _log_audit(self, line: str) -> None:
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            with open(self._audit_path, "a", encoding="utf-8") as f:
                f.write(f"{stamp} {line}\n")
        except OSError as exc:
            self.log.error("写 override 审计日志失败：%s", exc)

    def _open_whitelist_editor(self) -> None:
        try:
            from tray import open_config  # 延迟导入：guardian 模块级不依赖托盘库

            open_config(self.config_path)
            self.log.info("已打开配置文件供编辑白名单：%s", self.config_path)
        except Exception as exc:
            self.log.error("打开配置文件失败：%s", exc)

    # ------------------------------------------------------------------ 热重载

    def _stat_mtime(self) -> float | None:
        try:
            return os.stat(self.config_path).st_mtime
        except OSError:
            return None

    def _maybe_reload_config(self) -> None:
        mtime = self._stat_mtime()
        if mtime is None or mtime == self._config_mtime:
            return
        self._config_mtime = mtime
        try:
            new_cfg = load_config(self.config_path)
        except ConfigError as exc:
            self.log.error("配置热重载失败（保留旧配置）：%s", exc)
            return
        old = self.config
        self.config = new_cfg
        self._counter = core_checks.CheckCounter(
            new_cfg.pass_confirm_count, new_cfg.fail_unreachable_threshold)
        self._slow_every = max(
            1, round(new_cfg.slow_tick_sec / max(1, new_cfg.fast_tick_sec)))
        self._audit_path = Path(new_cfg.log_dir or "logs") / "override-audit.log"
        # 白名单/封禁段已更新：漂移告警交给新配置重新判定
        if self._gstate.drift_alarm:
            self._gstate = sm.GateState(
                self._gstate.state, False, self._gstate.on_override)
        changed = []
        v4_changed = old.blocked_cidrs_v4 != new_cfg.blocked_cidrs_v4
        v6_changed = old.blocked_cidrs_v6 != new_cfg.blocked_cidrs_v6
        domains_changed = old.claude_domains != new_cfg.claude_domains
        fakeip_range_changed = old.fakeip_range != new_cfg.fakeip_range
        if v4_changed:
            changed.append(f"blocked_cidrs_v4={new_cfg.blocked_cidrs_v4}")
        if v6_changed:
            changed.append(f"blocked_cidrs_v6={new_cfg.blocked_cidrs_v6}")
        if domains_changed:
            changed.append(f"claude_domains={new_cfg.claude_domains}")
        if fakeip_range_changed:
            changed.append(f"fakeip_range={new_cfg.fakeip_range}")
        if old.whitelist != new_cfg.whitelist:
            changed.append(f"whitelist={new_cfg.whitelist}")
        # 封禁段变化必须重建 WFP 规则（RemoteAddress 只在 create 时写入），
        # 否则日志“已更新”但规则仍封旧 CIDR（H5 断点）。
        if v4_changed or v6_changed:
            self._rebuild_blocked_rules(v4_changed, v6_changed)
        # claude_domains / fakeip_range 变化：CG-FakeIP 内容随之失效，立即
        # 按新配置重采集重建（放行态下重建为 Disabled，下轮迁移 enable 生效）。
        if domains_changed or fakeip_range_changed:
            self._fakeip_rule_ips = None  # 强制视为变化
            try:
                self._refresh_fakeip_rule()
            except Exception as exc:
                self.log.warning("CG-FakeIP 热重载重建失败（慢路径重试）：%s", exc)
        self.log.info("配置热重载完成 %s", "；".join(changed) or "（无字段变化）")

    def _rebuild_blocked_rules(self, v4: bool, v6: bool) -> None:
        """按当前期望状态重建封禁规则（create_rule 覆盖重建后恢复 Enabled/Disabled）。"""
        expected_enabled = not (
            self._gstate.state == sm.ALLOWED or self._gstate.on_override
        )
        if v4:
            if self._fw_tolerant("create_rule"):
                if not expected_enabled:
                    self._fw_tolerant("disable")
                self.log.info("CG-Global 已按新 blocked_cidrs_v4 重建")
        if v6:
            if self._fw_tolerant("create_rule_v6"):
                # CG-V6 语义：永久 Enabled（B-6），重建后必须恢复
                try:
                    with self._fw_lock:
                        self.fw.ensure_enabled_v6(self.config)
                except Exception as exc:
                    self.log.warning("CG-V6 重建后恢复 Enabled 失败：%s", exc)
                self.log.info("CG-V6 已按新 blocked_cidrs_v6 重建")

    # ------------------------------------------------------------------ 漂移监控

    def _drain_incoming(self) -> None:
        while True:
            try:
                item = self._incoming.get_nowait()
            except queue.Empty:
                return
            if item == _STOP:
                return
            if item == sm.DRIFT_DETECTED:
                self._apply_event(sm.DRIFT_DETECTED)

    def _drift_loop(self) -> None:
        """独立守护线程：DoH 每 doh_check_interval_min、RIPE 每 ripe_check_interval_hours。
        只产生 DRIFT_DETECTED 事件，绝不动规则（D-3）；失败不影响主循环（D-4）。
        每轮循环重读间隔配置：热重载改 doh/ripe 间隔立即生效（L2）。"""
        next_doh = 0.0  # 启动即查一次
        next_ripe = 0.0
        while not self._stop.is_set():
            doh_every = self.config.doh_check_interval_min * 60
            ripe_every = self.config.ripe_check_interval_hours * 3600
            now = time.time()
            if now >= next_doh:
                next_doh = now + doh_every
                self._doh_drift_check()
            if now >= next_ripe:
                next_ripe = now + ripe_every
                self._ripe_drift_check()
            self._stop.wait(timeout=min(30.0, max(1.0, doh_every / 10)))

    def _doh_drift_check(self) -> None:
        try:
            answers: list[str] = []
            for domain in self.config.claude_domains:
                r = self.dns.doh_resolve(domain)
                if r.ok:
                    answers.extend(r.addresses)
                else:
                    self.log.warning("DoH 解析 %s 失败（不影响门禁）：%s",
                                     domain, r.error)
            if not answers:
                return
            blocked = list(self.config.blocked_cidrs_v4) + list(self.config.blocked_cidrs_v6)
            # None = 本轮不做 RIPE diff（曾传 [] 导致空集 diff 全量误报"已不公告"）
            report = self._detect_drift(answers, None, blocked)
            self._handle_drift_report("DoH", report)
        except Exception as exc:
            self.log.warning("DoH 漂移检查异常（不影响门禁）：%s", exc)

    def _ripe_drift_check(self) -> None:
        try:
            r = self.ripe.fetch_announced_prefixes(self.config.asn)
            if not r.ok:
                self.log.warning("RIPE 查询失败（不影响门禁）：%s", r.error)
                return
            blocked = list(self.config.blocked_cidrs_v4) + list(self.config.blocked_cidrs_v6)
            report = self._detect_drift([], list(r.prefixes), blocked)
            self._handle_drift_report("RIPE", report)
        except Exception as exc:
            self.log.warning("RIPE 漂移检查异常（不影响门禁）：%s", exc)

    def _detect_drift(self, dns_answers, ripe_prefixes, blocked_cidrs):
        from core.drift import detect_drift

        return detect_drift(dns_answers, ripe_prefixes, blocked_cidrs)

    def _handle_drift_report(self, source: str, report) -> None:
        if not report.drift_detected:
            return
        for line in report.details:
            self.log.warning("漂移[%s] %s", source, line)
        # 只投递事件，不动规则（D-3）
        self._incoming.put(sm.DRIFT_DETECTED)

    # ------------------------------------------------------------------ 托盘推送

    def _push_tray(self) -> None:
        if self.tray is None:
            return
        try:
            from tray import State, StateEvent

            state_map = {
                sm.BLOCKED: State.BLOCKED,
                sm.ALLOWED: State.ALLOWED,
            }
            evt = StateEvent(
                state=state_map[self._gstate.state],
                exit_ip=self._last_echo_ip or "未知",
                # 白名单命中 = 上次慢路径的真实判定；从未探测过（None）
                # 显示未命中。曾误用 bool(_last_echo_ip)：只要探到过出口
                # IP 就显示"是"，出口变脏时也错报"命中"（用户实测发现）。
                whitelist_hit=self._last_echo_in_whitelist is True,
                dns_leak_ip=self._last_dns_ip,
                checks=dict(self._last_checks),
                paused=self.paused,
                drift=self._gstate.drift_alarm,
                override_active=self._gstate.on_override,
                # 启动确认期：仍在拦截但检查已全部通过（等待连续确认放行）
                confirming=(self._gstate.state == sm.BLOCKED
                            and bool(self._last_checks)
                            and all(v for v in self._last_checks.values())),
            )
            self.tray.push_event(evt)
        except Exception as exc:
            self.log.debug("托盘推送失败（不影响守护）：%s", exc)


# ---------------------------------------------------------------------- 自检

def selfcheck(config: Config, logger: logging.Logger | None = None) -> int:
    """--check 自检模式：跑一轮快慢检查并打印结果后退出。

    不启动托盘、不修改防火墙（不发 enable/disable/ensure）。
    输出格式：主结论（防火墙状态 + 大白话原因）在最上面，
    技术细节放在分隔线之后供排障（文案统一来自 core.messages）。
    """
    log = logger or logging.getLogger(_LOGGER_NAME)
    if not log.handlers:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    results: dict[str, bool | None] = {}
    exit_ip: str | None = None
    in_whitelist: bool | None = None
    echo_ok: bool | None = None
    dns_leak_ip: str | None = None

    # ① mihomo 进程
    try:
        mihomo = netprobe.check_mihomo_process(config.mihomo_process)
    except Exception as exc:
        mihomo = False
        log.info("[warn] mihomo 检查异常: %s", exc)
    results["mihomo进程"] = mihomo

    # ② TUN 网卡
    tun_ok, tun_name = netprobe.check_tun_adapter(
        config.tun_adapter_keywords, config.fakeip_range)
    results["TUN网卡"] = tun_ok

    # ③ fake-ip 生效
    fk = dnscheck.check_fakeip(config.claude_domains[0], config.fakeip_range)
    fk_ok = bool(fk.ok and fk.in_fakeip_range)
    results["fake-ip"] = fk_ok

    # ④ echo 出口 IP + 白名单三分法
    echo = netprobe.probe_echo_endpoints(list(config.echo_endpoints))
    echo_ok = echo.ok
    results["echo出口"] = echo_ok
    if echo.ok:
        exit_ip = echo.ip
        in_whitelist = policy.classify(
            echo.ip, list(config.whitelist)) == policy.CLEAN

    fast_ok = mihomo and tun_ok

    # ⑤ DNS 出口探针：递归出口不在白名单 → 泄漏，与出口脏同权
    dns_verdict, dns_probe = dnscheck.check_dns_egress(
        config.dns_probe_domain,
        list(config.dns_whitelist or config.whitelist))
    dns_leak_ip = dns_probe.egress_ip if dns_probe.ok else None
    results["DNS出口干净"] = dns_verdict == policy.CLEAN

    # ---- 主结论（第一行防火墙状态 + 大白话原因）----
    # 主结论看全量检查：echo 判定 DIRTY 也算“防火墙应当拦截”（排除法：
    # 其余各项都正常时，不干净只能来自出口 IP 不在白名单）。
    # 检查⑤ DNS 出口脏同权：akamai whoami 递归出口不在白名单 → 同样阻断。
    everything_else_ok = mihomo and tun_ok and fk_ok
    should_block = not fast_ok or (
        echo_ok is not None and in_whitelist is False and everything_else_ok
    ) or (
        dns_verdict == policy.DIRTY and everything_else_ok
    )
    status = messages.Status(
        blocking=should_block,
        proxy_ok=mihomo,
        tunnel_ok=tun_ok,
        dns_ok=fk_ok,
        dns_leak_ip=dns_leak_ip if dns_verdict == policy.DIRTY else None,
        probe_ok=echo_ok,
        exit_ip=exit_ip,
        in_whitelist=in_whitelist,
    )
    print(messages.status_line(status))
    print(messages.reason_line(status))
    if not should_block:
        print("（自检为只读探测，不改变防火墙当前状态）")

    # ---- 技术细节（排障用）----
    print()
    print(messages.TECH_SEPARATOR)
    print(f"① mihomo 进程 ({config.mihomo_process}): "
          f"{'存活' if mihomo else '未运行'}")
    print(f"② TUN 网卡: {'存在' if tun_ok else '不存在'}"
          + (f"（{tun_name}）" if tun_ok and tun_name else ""))
    print(f"③ fake-ip 生效 ({config.claude_domains[0]}): "
          f"{'是' if fk_ok else '否'} ips={fk.resolved_ips}"
          + (f" error={fk.error}" if fk.error else ""))
    # ③' CG-FakeIP：全域名 fake-ip 集合 + 规则状态（状态查询需管理员）
    fakeips = collect_fakeips(config, log)
    print(f"③' CG-FakeIP 集合 ({len(fakeips)} 个): "
          f"{list(fakeips) or '空（Clash 未运行或返回真实 IP）'}")
    try:
        fw_status = fw_mod.get_status_fakeip(config)
        print(f"    规则 {config.rule_name_fakeip}: {fw_status}")
    except Exception as exc:
        print(f"    规则 {config.rule_name_fakeip}: 查询失败（{exc}）")
    if echo.ok:
        verdict = policy.classify(echo.ip, list(config.whitelist))
        print(f"④ echo 出口 IP: {echo.ip}（{echo.endpoint}）→ 白名单判定: {verdict}")
    else:
        print(f"④ echo 出口 IP: 不可达（{echo.error}）")
    print(f"⑤ DNS 出口探针 ({config.dns_probe_domain}): "
          f"判定={dns_verdict} 解析出口={dns_probe.egress_ip or '未知'}"
          + (f" records={dns_probe.records}" if dns_probe.records else "")
          + (f" error={dns_probe.error}" if dns_probe.error else ""))
    print(f"\n快路径判定: {'正常' if fast_ok else '失败（将立即阻断）'}")
    readable = {k: {True: "通过", False: "未通过"}.get(v, "未探测")
                for k, v in results.items()}
    print(f"五项检查: {readable}")
    return 0 if fast_ok else 1
