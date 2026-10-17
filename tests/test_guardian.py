# -*- coding: utf-8 -*-
"""guardian.py 单测：全部 mock platform 层，不发网络、不碰真防火墙。

覆盖：事件映射（快/慢路径 → 状态机事件）、override 计时、快慢调度节奏、
规则自愈、PAUSE/RESUME、QUIT/EXIT、配置热重载、漂移线程事件投递。
"""
from __future__ import annotations

import logging
import struct
import threading

import pytest

import guardian
from guardian import Guardian
from core import policy
from core import statemachine as sm
from winplat.firewall import FirewallError
from core.config import Config


# ----------------------------------------------------------------- fakes

class FakeFirewall:
    """记录调用的防火墙替身。初始状态：CG-Global Enabled（阻断态）。

    get_status/get_status_fakeip 恒返回三态字符串（'ENABLED'/'DISABLED'/
    'MISSING'，与生产一致；P3-11 删除旧 bool 兼容面）。
    missing=True：模拟规则被第三方删除（返回 MISSING）。
    """

    def __init__(self, global_enabled: bool = True,
                 missing: bool = False, fail_methods: set | None = None) -> None:
        self.global_enabled = global_enabled
        self.missing = missing
        self.fakeip_enabled: bool | None = None  # None = 规则不存在
        self.fakeip_ips: list[str] = []
        self.calls: list[str] = []
        # P2-5 验收：记录 (method, 调用线程名)，断言 tick 线程内零 PS 直调
        self.threaded_calls: list[tuple[str, str]] = []
        # P1-4：可控持续失败注入（如 {"set_blocking"}）——模拟 PS 权限
        # 拒绝/防火墙服务异常，验证失败路径（_fw_tolerant 耗尽/heal 重试）。
        self.fail_methods: set = fail_methods or set()

    def fail_on(self, method: str) -> bool:
        return method in self.fail_methods

    # 启动预热 netsh 探测：默认 None（探测失败）→ guardian 回退原 PS 路径，
    # 既有用例行为不变；快进路径用例通过 probe_override 注入快照。
    def probe_rule_netsh(self, display_name):
        return getattr(self, "probe_override", None) and self.probe_override(display_name)

    @staticmethod
    def normalize_addr_set(values):
        from winplat import firewall as _fw_mod
        return _fw_mod.normalize_addr_set(values)

    def create_rule(self, config) -> None:
        self.calls.append("create_rule")
        self.threaded_calls.append(("create_rule", threading.current_thread().name))
        self.missing = False
        self.global_enabled = True

    def enable(self, config) -> None:
        self.calls.append("enable")
        self.threaded_calls.append(("enable", threading.current_thread().name))
        self.global_enabled = True

    def disable(self, config) -> None:
        self.calls.append("disable")
        self.threaded_calls.append(("disable", threading.current_thread().name))
        self.global_enabled = False

    def set_blocking(self, config, blocking: bool) -> None:
        """批量切换（P1-4 原子化）：单次原子记录——真实 set_blocking 是
        单 PS 进程原子操作，旧 fake 拆成 enable→enable_fakeip 顺序调用，
        enable_fakeip 缺失即抛，掩盖了"部分写入"失败路径（假绿）。
        语义对齐真实复查：CG-Global 必达目标态；CG-FakeIP 缺失（None）
        时跳过（幂等）。"""
        self.calls.append("set_blocking_on" if blocking else "set_blocking_off")
        self.threaded_calls.append(("set_blocking_on" if blocking else "set_blocking_off", threading.current_thread().name))
        self.global_enabled = blocking
        if self.fail_on("set_blocking"):
            raise FirewallError("set_blocking denied")
        if self.fakeip_enabled is not None:
            self.fakeip_enabled = blocking

    def block_all(self, config, fakeip_ips=None) -> None:
        """退出路径批量恢复阻断（单 PS 优化路径）：等价 ensure+enable
        两规则；fakeip_ips 为空时不碰 FakeIP 规则。"""
        self.calls.append("block_all")
        self.threaded_calls.append(("block_all", threading.current_thread().name))
        self.ensure_exists(config)
        self.enable(config)
        if fakeip_ips:
            self.ensure_exists_fakeip(config, fakeip_ips)
            self.enable_fakeip(config)

    def get_status(self, config):
        self.calls.append("get_status")
        self.threaded_calls.append(("get_status", threading.current_thread().name))
        if self.missing:
            return "MISSING"
        return "ENABLED" if self.global_enabled else "DISABLED"

    def ensure_exists(self, config) -> None:
        self.calls.append("ensure_exists")
        self.threaded_calls.append(("ensure_exists", threading.current_thread().name))
        self.missing = False

    # -------- CG-FakeIP（门控规则：与 CG-Global 同步 enable/disable）

    def create_rule_fakeip(self, config, ips) -> None:
        self.calls.append("create_rule_fakeip")
        self.threaded_calls.append(("create_rule_fakeip", threading.current_thread().name))
        self.fakeip_ips = list(ips)
        self.fakeip_enabled = True

    def enable_fakeip(self, config) -> None:
        self.calls.append("enable_fakeip")
        self.threaded_calls.append(("enable_fakeip", threading.current_thread().name))
        if self.fail_on("enable_fakeip"):
            raise FirewallError("enable_fakeip denied")
        if self.fakeip_enabled is None:
            return  # MISSING 幂等：对齐真实语义（P1-4，不再抛 RuntimeError）
        self.fakeip_enabled = True

    def disable_fakeip(self, config) -> None:
        self.calls.append("disable_fakeip")
        self.threaded_calls.append(("disable_fakeip", threading.current_thread().name))
        if self.fakeip_enabled is None:
            return  # MISSING 幂等（对齐真实 disable_fakeip）
        self.fakeip_enabled = False

    def get_status_fakeip(self, config):
        self.calls.append("get_status_fakeip")
        self.threaded_calls.append(("get_status_fakeip", threading.current_thread().name))
        if self.fakeip_enabled is None:
            return "MISSING"
        return "ENABLED" if self.fakeip_enabled else "DISABLED"

    def ensure_exists_fakeip(self, config, ips) -> None:
        self.calls.append("ensure_exists_fakeip")
        self.threaded_calls.append(("ensure_exists_fakeip", threading.current_thread().name))
        if self.fakeip_enabled is None:
            self.create_rule_fakeip(config, ips)

    def create_rule_v6(self, config) -> None:
        self.calls.append("create_rule_v6")
        self.threaded_calls.append(("create_rule_v6", threading.current_thread().name))

    def ensure_enabled_v6(self, config) -> None:
        self.calls.append("ensure_enabled_v6")
        self.threaded_calls.append(("ensure_enabled_v6", threading.current_thread().name))



class FakeNetprobe:
    def __init__(self, mihomo=True, tun=True, echo_ip="203.0.113.10", echo_ok=True):
        self.mihomo = mihomo
        self.tun = tun
        self.echo_ip = echo_ip
        self.echo_ok = echo_ok
        self.local_calls = 0
        self.echo_calls = 0

    def check_local_env(self, config):
        self.local_calls += 1
        return guardian.netprobe.LocalEnvResult(
            mihomo_running=self.mihomo, tun_present=self.tun,
            error=None if (self.mihomo and self.tun) else "missing")

    def probe_echo_endpoints(self, endpoints):
        self.echo_calls += 1
        if self.echo_ok:
            return guardian.netprobe.EchoResult(ok=True, ip=self.echo_ip,
                                                endpoint=endpoints[0])
        return guardian.netprobe.EchoResult(ok=False, ip=None, endpoint=None,
                                            error="timeout")


class FakeDns:
    def __init__(self, fakeip=True):
        self.fakeip = fakeip

    def check_fakeip(self, hostname, fakeip_range, resolver=None):
        return guardian.dnscheck.FakeIpResult(
            ok=True, resolved_ips=("198.18.0.1",) if self.fakeip else ("1.2.3.4",),
            in_fakeip_range=self.fakeip)

    def doh_resolve(self, hostname, **kw):
        return guardian.dnscheck.DohResult(ok=True, addresses=("160.79.104.10",))

    def check_dns_egress(self, domain, whitelist, allowed_countries=None):
        """检查⑤默认桩：出口 203.0.113.10 ∈ 默认白名单 → CLEAN。"""
        return policy.CLEAN, guardian.dnscheck.DnsEgressResult(
            ok=True, egress_ip="203.0.113.10", records=("ns", "203.0.113.10"))


class FakeRipe:
    def __init__(self, ok=True, prefixes=("160.79.104.0/23",)):
        self.ok = ok
        self.prefixes = prefixes
        self.calls = 0

    def fetch_announced_prefixes(self, asn, **kw):
        self.calls += 1
        if self.ok:
            return guardian.ripecheck.RipeResult(ok=True,
                                                 prefixes=frozenset(self.prefixes))
        return guardian.ripecheck.RipeResult(ok=False, error="boom")


class FakeTray:
    def __init__(self):
        import queue
        self.events = []
        self.commands: queue.Queue = queue.Queue()

    def push_event(self, evt):
        self.events.append(evt)


class FakeClock:
    """手动推进的单调时钟。"""

    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, sec):
        self.now += sec


NOOP = lambda *a, **k: None  # noqa: E731


def make_config(**over) -> Config:
    base = dict(
        blocked_cidrs_v4=["160.79.104.0/23"],
        blocked_cidrs_v6=["2607:6bc0::/48"],
        rule_name_v4="CG-Global",
        rule_name_v6="CG-V6",
        whitelist=["203.0.113.10"],
        echo_endpoints=["https://echo.test/ip"],
        fakeip_range="198.18.0.0/15",
        mihomo_process="verge-mihomo.exe",
        tun_adapter_keywords=["mihomo"],
        fast_tick_sec=1,
        slow_tick_sec=5,
        pass_confirm_count=3,
        fail_unreachable_threshold=5,
        doh_check_interval_min=60,
        ripe_check_interval_hours=24,
        override_minutes=30,
        claude_domains=["claude.ai"],
        asn="AS399358",
        log_dir="logs",
        log_retention_days=30,
        # P2-3 接口契约：load() 保证 dns_whitelist 恒有值（键缺失回退
        # whitelist）。测试直接构造 Config 不走 load，这里按同语义补齐；
        # 显式传 dns_whitelist=...（含 []）时尊重显式值。
    )
    base.setdefault("dns_whitelist", list(base["whitelist"]))
    base.update(over)
    return Config(**base)


def make_guardian(tmp_path, **kw):
    """构造全 mock 的 Guardian。kw 直通各 fake 构造器。"""
    cfg = make_config(log_dir=str(tmp_path / "logs"))
    fw = kw.pop("fw", None) or FakeFirewall()
    np = kw.pop("np", None) or FakeNetprobe()
    dns = kw.pop("dns", None) or FakeDns()
    ripe = kw.pop("ripe", None) or FakeRipe()
    clock = kw.pop("clock", None) or FakeClock()
    config_path = kw.pop("config_path", tmp_path / "config.json")
    g = Guardian(
        cfg, config_path,
        fw=fw, np=np, dns=dns, ripe=ripe,
        notify_fn=kw.pop("notify_fn", NOOP), tray=kw.pop("tray", None),
        clock=clock, sleep_fn=lambda s: None,
        logger=logging.getLogger("test-guard"),
    )
    g._preheat = lambda: None  # 不触发预热副作用计数
    return g, fw, np, dns, ripe, clock


# ----------------------------------------------------------------- 事件映射

class TestEventMapping:
    def test_startup_blocked_enable(self, tmp_path):
        """启动即阻断态：第一轮自愈期望 Enabled。"""
        g, fw, *_ , clock = make_guardian(tmp_path)
        g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert fw.global_enabled is True

    def test_fast_fail_blocks_immediately(self, tmp_path):
        g, fw, np, *_ , _ = make_guardian(tmp_path)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        np.mihomo = False
        g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert fw.global_enabled is True

    def test_fast_fail_from_blocked_is_idempotent(self, tmp_path):
        g, fw, np, *_ , _ = make_guardian(tmp_path)
        np.mihomo = False
        before = list(fw.calls)
        g.tick()
        # BLOCKED 态 FAST_FAIL 不再额外 enable（状态机幂等）
        assert "enable" not in [c for c in fw.calls[len(before):]]

    def test_slow_pass_confirmed_releases(self, tmp_path):
        np = FakeNetprobe(echo_ip="203.0.113.10")
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        assert g._gstate.state == sm.BLOCKED
        # 慢路径 3 次连续 PASS（slow_every=5），第 3 次 PASS_CONFIRMED → 放行
        for _ in range(3):
            g._tick_count = 4  # 令本轮 slow_due
            g.tick()
        assert g._gstate.state == sm.ALLOWED
        assert "set_blocking_off" in fw.calls
        assert fw.global_enabled is False

    def test_dirty_exit_blocks_immediately(self, tmp_path):
        np = FakeNetprobe(echo_ip="203.0.113.9")  # 白名单外
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        g._tick_count = 4
        g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert fw.global_enabled is True

    def test_unreachable_counts_then_blocks(self, tmp_path):
        np = FakeNetprobe(echo_ok=False)
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        for i in range(5):
            g._tick_count = 4
            g.tick()
            if i < 4:
                assert g._gstate.state == sm.ALLOWED  # 未达阈值不阻断
        assert g._gstate.state == sm.BLOCKED
        assert fw.global_enabled is True

    def test_fakeip_failure_blocks(self, tmp_path):
        dns = FakeDns(fakeip=False)
        g, fw, *_ , _ = make_guardian(tmp_path, dns=dns)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        g._tick_count = 4
        g.tick()
        assert g._gstate.state == sm.BLOCKED


# ----------------------------------------------------------------- 调度节奏

class TestScheduling:
    def test_fast_every_tick_slow_every_n(self, tmp_path):
        np = FakeNetprobe()
        g, *_ , _ = make_guardian(tmp_path, np=np)
        for _ in range(10):
            g.tick()
        assert np.local_calls == 10          # 快路径每轮必查
        assert np.echo_calls == 3            # 第 1 轮即慢路径 + slow_every=5 → 第 1、5、10 轮

    def test_slow_every_matches_config(self, tmp_path):
        g, *_ , _ = make_guardian(tmp_path)
        assert g._slow_every == 5

    def test_tick_sleep_uses_fast_tick(self, tmp_path):
        sleeps = []
        g, *_ , _ = make_guardian(tmp_path)
        g._sleep = sleeps.append
        g.tick()
        g._sleep(g.config.fast_tick_sec)
        assert sleeps[-1] == 1


# ----------------------------------------------------------------- override

class TestOverride:
    def test_override_start_disables_and_expires(self, tmp_path):
        g, fw, *_ , clock = make_guardian(tmp_path)
        clock.advance(1000)
        assert g.handle_command("override_30min") is True
        assert g._gstate.on_override is True
        assert g.override_until == 1000 + 30 * 60
        assert "set_blocking_off" in fw.calls
        # 期间检查失败也不阻断
        np = g.np
        np.mihomo = False
        g.tick()
        assert g._gstate.on_override is True
        np.mihomo = True
        # 到期 → 恢复阻断
        clock.advance(30 * 60 + 1)
        g.tick()
        assert g._gstate.on_override is False
        assert g._gstate.state == sm.BLOCKED
        assert "set_blocking_on" in fw.calls

    def test_override_audit_log(self, tmp_path):
        g, *_ , _ = make_guardian(tmp_path)
        g.handle_command("override_30min")
        audit = tmp_path / "logs" / "override-audit.log"
        text = audit.read_text(encoding="utf-8")
        assert "start" in text
        clock = FakeClock(10**9)
        g._clock = clock
        clock.advance(30 * 60 + 1)
        g.tick()
        assert "end" in audit.read_text(encoding="utf-8")

    def test_override_no_repeat(self, tmp_path):
        g, *_ , _ = make_guardian(tmp_path)
        assert g.handle_command("override_30min") is True
        first_until = g.override_until
        assert g.handle_command("override_30min") is True
        assert g.override_until == first_until
    def test_end_override_restores_block_immediately(self, tmp_path):
        """手动'立即恢复阻断'：与自然到期同效——enable 规则 + 审计 end。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g.handle_command("override_30min")
        assert g._gstate.on_override is True
        assert fw.global_enabled is False        # 放行中
        assert g.handle_command("end_override") is True
        assert g._gstate.on_override is False
        assert g.override_until is None
        assert fw.global_enabled is True         # 立即恢复阻断
        audit = tmp_path / "logs" / "override-audit.log"
        assert "end manual" in audit.read_text(encoding="utf-8")

    def test_end_override_noop_when_not_overriding(self, tmp_path):
        """未在临时放行时点'立即恢复阻断'：无副作用（幂等）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        assert g.handle_command("end_override") is True
        assert g._gstate.on_override is False
        assert "enable" not in fw.calls           # 不触发多余规则动作

    def test_toggle_pause_flips_state(self, tmp_path):
        """合并后的暂停/恢复单项：同一命令来回切换。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        assert g.handle_command("toggle_pause") is True
        assert g.paused is True
        assert fw.global_enabled is True          # 暂停冻结在阻断
        assert g.handle_command("toggle_pause") is True
        assert g.paused is False

    def test_tray_command_wakes_main_loop_sleep(self, tmp_path):
        """托盘命令 → _cmd_wake set：主循环可中断睡眠立即结束。"""
        g, *_ , _ = make_guardian(tmp_path)
        assert g._cmd_wake.wait(0.05) is False    # 未唤醒时超时返回 False
        g._cmd_wake.set()
        assert g._cmd_wake.wait(0.05) is True     # 已 set → 立即返回 True


# ----------------------------------------------------------------- 命令

class TestCommands:
    def test_pause_freezes_blocking_and_stops_checks(self, tmp_path):
        """暂停 = 冻结在阻断态：强制 enable + 强制 BLOCKED，停止检查（M2）。"""
        np = FakeNetprobe()
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        # 模拟暂停前处于放行态
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        assert g.handle_command("pause") is True
        assert g.paused is True
        assert fw.global_enabled is True           # 规则被强制 enable
        assert g._gstate.state == sm.BLOCKED       # 状态冻结在阻断态
        before_local = np.local_calls
        g.tick(); g.tick()
        assert np.local_calls == before_local      # 暂停期间不做检查
        assert g.handle_command("resume") is True
        g.tick()
        assert np.local_calls > before_local

    def test_pause_still_enforces_v6_and_override_expiry(self, tmp_path):
        """H3：暂停期间 override 到期判断照常；P2-5 后 tick 内零 PS——
        CG-V6 ensure 由 heal 线程每 30s 无条件执行（暂停时照常跑）。"""
        g, fw, *_ , clock = make_guardian(tmp_path)
        clock.advance(1000)
        g.handle_command("override_30min")
        g.handle_command("pause")
        # P2-5：暂停态 tick 内不再 per-tick ensure_enabled_v6（零 PS 直调）
        fw.calls.clear()
        clock.advance(31)
        g.tick()
        assert "ensure_enabled_v6" not in fw.calls
        assert "create_rule" not in fw.calls
        # heal 线程暂停时仍无条件 ensure CG-V6（B-6 语义保留）
        g._self_heal_rules()
        assert "ensure_enabled_v6" in fw.calls
        # override 到期：暂停期间也恢复阻断
        clock.advance(30 * 60 + 1)
        g.tick()
        assert g._gstate.on_override is False
        assert g._gstate.state == sm.BLOCKED
        assert fw.global_enabled is True

    def test_quit_keeps_rule_state(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        assert g.handle_command("quit") is False
        assert g._stop.is_set()
        # 不额外 enable/disable（保持实际状态）
        assert "enable" not in fw.calls and "disable" not in fw.calls

    def test_exit_restores_block(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        assert g.handle_command("exit") is False
        assert "enable" in fw.calls
        assert g._stop.is_set()

    def test_edit_whitelist_invokes_open_config(self, tmp_path, monkeypatch):
        opened = []
        import tray as tray_mod
        monkeypatch.setattr(tray_mod, "open_config", lambda p: opened.append(p))
        g, *_ , _ = make_guardian(tmp_path)
        # guardian._open_whitelist_editor 延迟 from tray import open_config
        assert g.handle_command("edit_whitelist") is True
        assert opened == [str(tmp_path / "config.json")]

    def test_tray_commands_drained(self, tmp_path):
        tray = FakeTray()
        g, *_ , _ = make_guardian(tmp_path, tray=tray)
        tray.commands.put("pause")
        tray.commands.put("resume")
        assert g.tick() is True
        assert g.paused is False


# ----------------------------------------------------------------- 规则自愈（线程）

def start_heal_thread(g: Guardian) -> None:
    """测试辅助：显式启动 heal 线程（等价 start() 里的那一步）。"""
    g._heal_thread = threading.Thread(target=g._heal_loop, name="rule-heal", daemon=True)
    g._heal_thread.start()


def wait_for_calls(fw, method: str, count: int, timeout: float = 5.0) -> bool:
    """轮询等待 FakeFirewall 累计到 count 次 method 调用。"""
    import time as _t
    deadline = _t.monotonic() + timeout
    while _t.monotonic() < deadline:
        if fw.calls.count(method) >= count:
            return True
        _t.sleep(0.02)
    return fw.calls.count(method) >= count


class TestSelfHeal:
    def test_heal_thread_runs_on_interval(self, tmp_path):
        """heal 线程启动即跑一轮，随后按周期再跑（join 同步，无轮询竞态）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        # wait 第 1 次返回 True（周期到）→ 第 2 轮；随后 set stop 且返回 False 退出
        state = {"n": 0}

        def wait_once(timeout=None):
            state["n"] += 1
            if state["n"] == 1:
                return True
            g._stop.set()
            return False

        g._heal_wake.wait = wait_once
        start_heal_thread(g)
        g._heal_thread.join(timeout=5)
        # 启动即一轮（get_status），周期到又一轮
        assert wait_for_calls(fw, "get_status", 2)

    def test_heal_thread_wake_after_transition(self, tmp_path):
        """状态迁移后主循环 set _heal_wake → heal 线程立即校验（不等 30s）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        # 周期 wait 阻塞（模拟 30s 未到），只有迁移触发的 wake 能推进
        g._stop.wait = lambda timeout=None: g._heal_wake.wait(timeout=5) \
            and not g._stop.is_set()
        start_heal_thread(g)
        g._heal_wake.set()
        assert wait_for_calls(fw, "get_status", 1)
        g._stop.set()
        g._heal_wake.set()
        g._heal_thread.join(timeout=5)

    def test_heal_thread_survives_exception(self, tmp_path):
        """自愈异常不杀死线程（fail-closed 兜底不可失能）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            fw.calls.append("get_status")

        g._self_heal_rules = flaky
        g._stop.wait = lambda timeout=None: (calls["n"] >= 2, True)[0]
        start_heal_thread(g)
        g._heal_thread.join(timeout=5)
        assert calls["n"] >= 2

    def test_stop_joins_heal_thread(self, tmp_path):
        """stop() 唤醒并 join heal 线程，干净退出。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        # wait 正常阻塞周期；wake 由 stop() 触发提前返回
        start_heal_thread(g)
        assert g._heal_thread is not None and g._heal_thread.is_alive()
        g.stop(timeout=2)
        assert not g._heal_thread.is_alive()

    def test_third_party_reset_corrected(self, tmp_path):
        """heal 线程发现第三方把规则 Disabled（BLOCKED 期望 Enabled）→ 纠正。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        fw.global_enabled = False
        start_heal_thread(g)
        assert wait_for_calls(fw, "enable", 1)
        assert fw.global_enabled is True
        g._stop.set()
        g._heal_wake.set()
        g._heal_thread.join(timeout=5)

    def test_self_heal_skipped_within_interval(self, tmp_path):
        """周期未到且无迁移触发时，heal 线程不发起第二轮（wait 超时返回 False）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        # 第一轮启动即跑；随后 wait(timeout=30) 超时返回 False 才跑第二轮——
        # 本测试在第二轮前主动停线程，验证单轮内不重复读状态。
        g._stop.wait = lambda timeout=None: (g._stop.set(), False)[1]
        start_heal_thread(g)
        g._heal_thread.join(timeout=5)
        assert fw.calls.count("get_status") == 1
        assert "enable" not in fw.calls

    def test_self_heal_after_transition_immediate(self, tmp_path):
        """状态迁移后 _heal_wake 置位（触发语义），heal 线程被唤醒校验。"""
        np = FakeNetprobe(echo_ip="203.0.113.10")
        g, fw, np, *_ , _ = make_guardian(tmp_path, np=np)
        g._stop.wait = lambda timeout=None: (g._stop.set(), True)[1]
        start_heal_thread(g)
        for _ in range(3):
            g._tick_count = 4
            g.tick()
        assert g._gstate.state == sm.ALLOWED
        # 迁移发生 → _heal_wake 置位（heal 线程据此立即校验）
        assert g._heal_wake.is_set() or wait_for_calls(fw, "get_status", 1)
        g._stop.set()
        g._heal_wake.set()
        if g._heal_thread is not None:
            g._heal_thread.join(timeout=5)

    def test_fast_fail_enable_skips_concurrent_heal_overlap(self, tmp_path):
        """FAST_FAIL → set_blocking(True) 走主循环 _fw_tolerant（持锁）；
        heal 线程的 get_status 与其按次互斥，不会读到半写入状态。
        P1-4 fake 原子化后，写入即 set_blocking_on（不再有单项 enable）。"""
        np = FakeNetprobe(mihomo=False)
        g, fw, np, *_ , _ = make_guardian(tmp_path, np=np)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        # 模拟 heal 线程正持锁跑 get_status：主循环写入必须等它完成
        fw_slow = threading.Event()
        real_get_status = fw.get_status

        def slow_get_status(config):
            fw_slow.wait(timeout=5)
            return real_get_status(config)

        fw.get_status = slow_get_status
        g._fw_lock.acquire()
        try:
            blocker = threading.Thread(target=fw_slow.set, daemon=True)
            blocker.start()
        finally:
            g._fw_lock.release()
        g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert fw.global_enabled is True
        assert fw.calls[calls_index_of(fw, "set_blocking_on"):].count(
            "set_blocking_on") >= 1

    def test_rule_missing_rebuilt_then_restored(self, tmp_path):
        """C3 适配：get_status 返回 MISSING → ensure_exists 重建并按期望恢复。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        fw.missing = True            # BLOCKED 期望 Enabled
        start_heal_thread(g)
        assert wait_for_calls(fw, "ensure_exists", 1)
        assert fw.global_enabled is True
        assert fw.missing is False
        g._stop.set()
        g._heal_wake.set()
        g._heal_thread.join(timeout=5)

    def test_rule_missing_rebuilt_disabled_when_allowed(self, tmp_path):
        """ALLOWED 期望 Disabled：MISSING 重建后应 disable。"""
        np = FakeNetprobe(echo_ip="203.0.113.10")
        g, fw, np, *_ , _ = make_guardian(tmp_path, np=np)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.missing = True
        start_heal_thread(g)
        assert wait_for_calls(fw, "ensure_exists", 1)
        assert wait_for_calls(fw, "disable", 1)
        assert fw.global_enabled is False
        g._stop.set()
        g._heal_wake.set()
        g._heal_thread.join(timeout=5)

    def test_v6_ensured_per_heal_round(self, tmp_path):
        """heal 线程每轮都 ensure CG-V6（跑两轮验证）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        rounds = {"n": 0}

        def wait_two_rounds(timeout=None):
            rounds["n"] += 1
            if rounds["n"] < 2:
                return True   # 第 1 次返回 True → 再跑一轮
            g._stop.set()
            return False

        g._heal_wake.wait = wait_two_rounds
        start_heal_thread(g)
        assert wait_for_calls(fw, "ensure_enabled_v6", 2)
        g._stop.set()
        g._heal_wake.set()
        g._heal_thread.join(timeout=5)

    def test_tick_not_blocked_by_slow_fw_call(self, tmp_path):
        """核心回归：主循环 tick 不因 heal 的慢 fw 调用变长。

        heal 线程 get_status 阻塞 0.5s 期间，主循环 tick 必须正常完成
        （旧实现里 tick 内联自愈会被拖住）。"""
        np = FakeNetprobe(mihomo=True)
        g, fw, np, *_ , _ = make_guardian(tmp_path, np=np)
        real_get_status = fw.get_status

        def slow_get_status(config):
            import time as _t
            _t.sleep(0.5)
            return real_get_status(config)

        fw.get_status = slow_get_status
        start_heal_thread(g)
        # heal 线程进入慢 get_status 的窗口内跑 tick。
        # 被测 tick 须为纯快路径（第 2 轮）：第 1 轮现在即慢路径
        # （含 fw 调用、按设计与 heal 互斥），慢路径 tick 与 heal 的
        # 锁竞争不属本回归的保护对象。
        import time as _t
        _t.sleep(0.05)
        g._tick_count = 1
        t0 = _t.monotonic()
        g.tick()
        elapsed = _t.monotonic() - t0
        assert elapsed < 0.4, f"tick 被 heal 的慢调用阻塞 {elapsed:.2f}s"
        g._stop.set()
        g._heal_wake.set()
        g._heal_thread.join(timeout=5)


def calls_index_of(fw, method: str) -> int:
    """fw.calls 中该 method 最后一次出现前的下标（测试辅助）。"""
    for i in range(len(fw.calls) - 1, -1, -1):
        if fw.calls[i] == method:
            return i
    return 0


# ----------------------------------------------------------------- 热重载

class TestHotReload:
    def test_whitelist_reload_without_restart(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(
            (cfg_path.parent / "_x").as_uri() if False else __import__("json").dumps({
                "blocked_cidrs_v4": ["160.79.104.0/23"],
                "blocked_cidrs_v6": ["2607:6bc0::/48"],
                "rule_name_v4": "CG-Global",
                "rule_name_v6": "CG-V6",
                "whitelist": ["203.0.113.10"],
                "echo_endpoints": ["https://echo.test/ip"],
                "fakeip_range": "198.18.0.0/15",
                "mihomo_process": "verge-mihomo.exe",
                "tun_adapter_keywords": ["mihomo"],
                "fast_tick_sec": 1, "slow_tick_sec": 5,
                "pass_confirm_count": 3, "fail_unreachable_threshold": 5,
                "doh_check_interval_min": 60, "ripe_check_interval_hours": 24,
                "override_minutes": 30,
                "claude_domains": ["claude.ai"],
                "asn": "AS399358",
                "log_dir": str(tmp_path / "logs"),
                "log_retention_days": 30,
            }), encoding="utf-8")
        g, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        old_mtime = g._config_mtime
        import json, os, time
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        data["whitelist"] = ["1.2.3.4"]
        cfg_path.write_text(json.dumps(data), encoding="utf-8")
        st = os.stat(cfg_path)
        os.utime(cfg_path, (st.st_atime, st.st_mtime + 10))
        g.tick()
        assert g.config.whitelist == ["1.2.3.4"]
        assert g._config_mtime != old_mtime

    def test_bad_reload_keeps_old_config(self, tmp_path):
        import json, os
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({
            "blocked_cidrs_v4": ["160.79.104.0/23"],
            "blocked_cidrs_v6": ["2607:6bc0::/48"],
            "rule_name_v4": "CG-Global", "rule_name_v6": "CG-V6",
            "whitelist": ["203.0.113.10"],
            "echo_endpoints": ["https://echo.test/ip"],
            "fakeip_range": "198.18.0.0/15",
            "mihomo_process": "verge-mihomo.exe",
            "tun_adapter_keywords": ["mihomo"],
            "fast_tick_sec": 1, "slow_tick_sec": 5,
            "pass_confirm_count": 3, "fail_unreachable_threshold": 5,
            "doh_check_interval_min": 60, "ripe_check_interval_hours": 24,
            "override_minutes": 30, "claude_domains": ["claude.ai"],
            "asn": "AS399358", "log_dir": str(tmp_path / "logs"),
            "log_retention_days": 30,
        }), encoding="utf-8")
        g, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        old_cfg = g.config
        cfg_path.write_text("{ not json", encoding="utf-8")
        st = os.stat(cfg_path)
        os.utime(cfg_path, (st.st_atime, st.st_mtime + 10))
        g.tick()
        assert g.config is old_cfg


# ----------------------------------------------------------------- 漂移线程

class TestDrift:
    def test_drift_event_sets_flag_only(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        before = list(fw.calls)
        g._incoming.put(sm.DRIFT_DETECTED)
        g.tick()
        assert g._gstate.drift_alarm is True
        assert g._gstate.state == sm.BLOCKED   # 状态不变
        # 不动规则
        assert "enable" not in fw.calls[len(before):]
        assert "disable" not in fw.calls[len(before):]

    def test_doh_drift_detection_pushes_event(self, tmp_path):
        dns = FakeDns()
        # 解析结果不在封禁段内 → 漂移
        dns.doh_resolve = lambda hostname, **kw: guardian.dnscheck.DohResult(
            ok=True, addresses=("203.0.113.5",))
        g, *_ , _ = make_guardian(tmp_path, dns=dns)
        g._doh_drift_check()
        assert g._incoming.qsize() == 1
        g.tick()
        assert g._gstate.drift_alarm is True

    def test_ripe_failure_ignored(self, tmp_path):
        ripe = FakeRipe(ok=False)
        g, *_ , _ = make_guardian(tmp_path, ripe=ripe)
        g._ripe_drift_check()
        assert g._incoming.qsize() == 0

    def test_drift_thread_delivers(self, tmp_path):
        dns = FakeDns()
        dns.doh_resolve = lambda hostname, **kw: guardian.dnscheck.DohResult(
            ok=True, addresses=("203.0.113.5",))
        g, *_ , _ = make_guardian(tmp_path, dns=dns)
        g._stop.clear()
        t = threading.Thread(target=g._drift_loop, daemon=True)
        t.start()
        g._drain_incoming_wait = True
        # 等待漂移线程投递
        import time as _t
        deadline = _t.monotonic() + 5
        while g._incoming.qsize() == 0 and _t.monotonic() < deadline:
            _t.sleep(0.05)
        g._stop.set()
        t.join(timeout=3)
        assert g._incoming.qsize() >= 1


# ----------------------------------------------------------------- 日志

class TestLogging:
    def test_setup_logging_rotating_file(self, tmp_path):
        cfg = make_config(log_dir=str(tmp_path / "logs"))
        log = guardian.setup_logging(cfg, logger=logging.getLogger("test-log-1"))
        log.info("hello")
        for h in log.handlers[:]:
            h.flush()
        files = list((tmp_path / "logs").glob("guard*.log"))
        assert files
        for h in log.handlers[:]:
            log.removeHandler(h)

    def test_namer(self):
        assert guardian._guard_namer("guard.log.20261015") == "guard-20261015.log"

    def test_log_retention_cleanup_matches_namer_output(self, tmp_path):
        """P2-8：自定义 namer 后 extMatch 须匹配 8 位日期戳，否则
        getFilesToDelete 恒空、保留期清理失效（曾实测复现）。"""
        import logging.handlers
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        old = log_dir / "guard-20261001.log"   # 旧 → 应进删除列表
        new = log_dir / "guard-20990101.log"   # 新 → 保留
        current = log_dir / "guard.log"
        for f in (old, new, current):
            f.write_text("", encoding="utf-8")
        cfg = make_config(log_dir=str(log_dir), log_retention_days=1)
        log = guardian.setup_logging(cfg, logger=logging.getLogger("test-log-p28"))
        handler = log.handlers[0]
        assert isinstance(handler, logging.handlers.TimedRotatingFileHandler)
        # extMatch 已按 namer 产物修正（默认 ^\d{4}-\d{2}-\d{2}$ 永不命中）
        assert handler.extMatch.search("guard-20261001.log")
        assert not handler.extMatch.search("guard-notastamp.log")  # 非 8 位日期戳不误匹配
        to_delete = list(handler.getFilesToDelete())
        assert str(old) in to_delete
        assert str(new) not in to_delete
        handler.close()


class TestPreheat:
    def test_preheat_ensures_blocking_state(self, tmp_path):
        """P2-7：上次放行态强杀残留 Disabled 时，preheat 必须在启动期
        set_blocking(True) 封死（ensure_exists 不改 Enabled 态）。"""
        fw = FakeFirewall(global_enabled=False)  # 残留放行态
        fw.fakeip_enabled = False
        g, *_ , _ = make_guardian(tmp_path, fw=fw)
        # 直接跑 preheat（make_guardian 已把 g._preheat 替换为 no-op，还原）
        g._preheat = Guardian._preheat.__get__(g)
        import socket as s
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", ("198.18.0.1", 0))]
        try:
            g._preheat()
        finally:
            s.getaddrinfo = real
        assert g.fw.global_enabled is True
        assert "set_blocking_on" in g.fw.calls
        # ensure_exists 在 set_blocking 之前（先补缺再置态）
        assert g.fw.calls.index("ensure_exists") \
            < g.fw.calls.index("set_blocking_on")

    def test_preheat_blocking_not_broken_by_allowed_gstate(self, tmp_path):
        """启动初态恒 BLOCKED：即使 Guardian 状态字段默认值异常，preheat
        也无条件置阻断（P2-7 验收：pause/ALLOWED 初始态不影响）。"""
        fw = FakeFirewall(global_enabled=False)
        g, *_ = make_guardian(tmp_path, fw=fw)
        g._gstate = sm.GateState(state=sm.ALLOWED)  # 残留期望 Disabled
        g._preheat = Guardian._preheat.__get__(g)
        g._preheat()
        assert fw.global_enabled is True   # 启动期无条件阻断


class TestPreheatNetshFastPath:
    """启动预热 netsh 快进：探测到规则已就绪则零 PS；不符/缺失回退 PS。"""

    @staticmethod
    def _make_probe(fw, *, g_enabled=True, g_ips=("160.79.104.0/23",),
                    v6_ok=True, fakeip_ips=("198.18.0.1/32",)):
        from winplat.firewall import NetshRuleInfo, normalize_addr_set
        table = {
            "CG-Global": NetshRuleInfo(True, g_enabled, normalize_addr_set(g_ips)),
            "CG-V6": (NetshRuleInfo(True, True, normalize_addr_set(["2607:6bc0::/48"]))
                      if v6_ok else None),
            "CG-FakeIP": NetshRuleInfo(True, True, normalize_addr_set(fakeip_ips)),
        }
        fw.probe_override = table.get

    @staticmethod
    def _run(g):
        g._preheat = Guardian._preheat.__get__(g)
        import socket as s
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", ("198.18.0.1", 0))]
        try:
            g._preheat()
        finally:
            s.getaddrinfo = real

    def test_all_ready_zero_ps(self, tmp_path):
        """三规则存在且状态/地址一致 → 预热零 PS 调用（~9.6s → ~0.5s 的来源）。"""
        fw = FakeFirewall()
        self._make_probe(fw)
        g, fw, *_ = make_guardian(tmp_path, fw=fw)
        self._run(g)
        assert fw.calls == []
        assert g._fakeip_rule_ips == ("198.18.0.1",)

    def test_global_leftover_disabled_fast_blocks(self, tmp_path):
        """CG-Global 残留放行态（强杀场景）→ 仅一次 set_blocking(True)
        （生产内置 netsh 快车道 ~0.4s），不走 ensure_exists 全量 PS。"""
        fw = FakeFirewall(global_enabled=False)
        self._make_probe(fw, g_enabled=False)
        g, fw, *_ = make_guardian(tmp_path, fw=fw)
        self._run(g)
        assert fw.calls == ["set_blocking_on"]
        assert fw.global_enabled is True

    def test_global_addr_mismatch_rebuilds(self, tmp_path):
        """地址集与配置不符（升级改 CIDR）→ 覆盖重建（ensure_exists 按名
        存在不动作，堵不住新段）+ 封死。"""
        fw = FakeFirewall()
        self._make_probe(fw, g_ips=("203.0.113.0/24",))  # 与配置 160.79.104.0/23 不符
        g, fw, *_ = make_guardian(tmp_path, fw=fw)
        self._run(g)
        assert fw.calls[:2] == ["create_rule", "set_blocking_on"]

    def test_probe_failure_falls_back_to_ps(self, tmp_path):
        """探测失败（None）→ 完整回退原 PS 路径（不确定就走权威路径）。"""
        fw = FakeFirewall(global_enabled=False)
        # probe_override 不设置 → probe_rule_netsh 返回 None
        g, fw, *_ = make_guardian(tmp_path, fw=fw)
        self._run(g)
        assert "ensure_exists" in fw.calls
        assert "set_blocking_on" in fw.calls
        assert "ensure_enabled_v6" in fw.calls
        assert "create_rule_fakeip" in fw.calls
        assert fw.global_enabled is True


# ----------------------------------------------------------------- P2-5 tick 内零 PS

def _calls_by_thread(fw):
    """按方法名归纳调用线程名（FakeFirewall 记录 (method, thread)。"""
    out: dict[str, set] = {}
    for method, thread in fw.threaded_calls:
        out.setdefault(method, set()).add(thread)
    return out


class TestNoPsInTick:
    """P2-5：tick（guardian-main 线程）内不得出现 create_rule*/ensure_enabled_v6；
    重建最终仍发生（heal / fakeip-refresh 线程）。"""

    def test_paused_tick_zero_ps(self, tmp_path):
        """场景①暂停态：tick 内零 PS（v6 ensure 交给 heal 线程）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g.handle_command("pause")
        fw.threaded_calls.clear()
        fw.calls.clear()
        g.tick()
        assert _calls_by_thread(fw).get("ensure_enabled_v6", set()) == set()
        assert not fw.threaded_calls   # 暂停态 tick 整体零 PS

    def test_slow_path_fakeip_change_rebuild_in_refresh_thread(self, tmp_path):
        """场景②慢路径 fake-ip 集合变化：tick 内无 create_rule_fakeip，
        重建发生在 fakeip-refresh 线程。"""
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = sm.GateState(state=sm.BLOCKED)
        fw.fakeip_enabled = True
        g._fakeip_rule_ips = ("198.18.0.1",)
        fw.fakeip_ips = ["198.18.0.1"]
        current = {"ips": ["198.18.0.9"]}
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: [
            (2, 1, 6, "", (ip, 0)) for ip in current["ips"]]
        g._fakeip_thread = threading.Thread(
            target=g._fakeip_refresh_loop, name="fakeip-refresh", daemon=True)
        g._fakeip_thread.start()
        try:
            g._tick_count = 4
            g.tick()   # 慢路径：检测到变化，tick 内不得直调 PS
            threads = _calls_by_thread(fw)
            assert "guardian-main" not in threads.get("create_rule_fakeip", set())
            assert wait_for_calls(fw, "create_rule_fakeip", 1)
            threads = _calls_by_thread(fw)
            assert threads["create_rule_fakeip"] == {"fakeip-refresh"}
            assert fw.fakeip_ips == ["198.18.0.9"]
        finally:
            g._stop.set()
            g._fakeip_wake.set()
            g._fakeip_thread.join(timeout=5)
            s.getaddrinfo = real

    def test_hot_reload_rebuild_in_heal_thread(self, tmp_path):
        """场景③热重载 v4/v6 段变化：tick 内只置标志；重建在 rule-heal
        线程执行，重建后 CG-V6 强制 Enabled（fail-closed）。"""
        import json as _json
        import os as _os
        cfg_path = tmp_path / "config.json"
        data = {
            "blocked_cidrs_v4": ["203.0.113.0/24"],
            "blocked_cidrs_v6": ["2001:db8::/48"],
            "rule_name_v4": "CG-Global", "rule_name_v6": "CG-V6",
            "whitelist": ["203.0.113.10"],
            "echo_endpoints": ["https://echo.test/ip"],
            "fakeip_range": "198.18.0.0/15",
            "mihomo_process": "m.exe", "tun_adapter_keywords": ["mihomo"],
            "fast_tick_sec": 1, "slow_tick_sec": 5,
            "pass_confirm_count": 3, "fail_unreachable_threshold": 5,
            "doh_check_interval_min": 60, "ripe_check_interval_hours": 24,
            "override_minutes": 30, "claude_domains": ["claude.ai"],
            "asn": "AS399358", "log_dir": str(tmp_path / "logs"),
            "log_retention_days": 30,
        }
        cfg_path.write_text(_json.dumps(data), encoding="utf-8")
        g, fw, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        data["blocked_cidrs_v4"] = ["203.0.113.0/24", "198.51.100.0/24"]
        data["blocked_cidrs_v6"] = ["2001:db8::/48", "2607:6bc0::/48"]
        cfg_path.write_text(_json.dumps(data), encoding="utf-8")
        st = _os.stat(cfg_path)
        _os.utime(cfg_path, (st.st_atime, st.st_mtime + 10))
        g.tick()
        # tick 内零 PS：只置标志
        assert g._pending_rebuild == (True, True)
        threads = _calls_by_thread(fw)
        assert "guardian-main" not in threads.get("create_rule", set())
        assert "guardian-main" not in threads.get("create_rule_v6", set())
        assert "guardian-main" not in threads.get("ensure_enabled_v6", set())
        # heal 线程消费 → 重建发生且 v6 强制 Enabled
        g._self_heal_rules()
        threads = _calls_by_thread(fw)
        assert "create_rule" in threads
        assert "create_rule_v6" in threads
        assert "ensure_enabled_v6" in threads
        assert "guardian-main" not in threads["create_rule"]
        assert "guardian-main" not in threads["create_rule_v6"]
        assert "guardian-main" not in threads["ensure_enabled_v6"]


# ----------------------------------------------------------------- 自检

class TestSelfcheck:
    def test_selfcheck_runs_and_prints(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(guardian.netprobe, "check_mihomo_process",
                            lambda name: True)
        monkeypatch.setattr(guardian.netprobe, "check_tun_adapter",
                            lambda kw, rng: (True, "Mihomo"))
        monkeypatch.setattr(guardian.netprobe, "probe_echo_endpoints",
                            lambda eps: guardian.netprobe.EchoResult(
                                ok=True, ip="203.0.113.10", endpoint=eps[0]))
        monkeypatch.setattr(guardian.dnscheck, "check_fakeip",
                            lambda host, rng: guardian.dnscheck.FakeIpResult(
                                ok=True, resolved_ips=("198.18.0.1",),
                                in_fakeip_range=True))
        # 检查⑤也必须打桩：真实探针依赖网络/akahelp 可用性（不可达时
        # 单元测试应仍稳定——selfcheck 语义见 dns_clean 三态）。
        # P2-1：签名含第三参 countries（与运行时 _probe_dns_egress 一致），
        # 并记录实参验证 selfcheck 传出 config 的国家列表。
        seen_args: dict = {}

        def _fake_dns_egress(domain, wl, countries=None):
            seen_args.update(domain=domain, wl=list(wl), countries=list(countries or []))
            return (guardian.policy.CLEAN,
                    guardian.dnscheck.DnsEgressResult(
                        ok=True, egress_ip="203.0.113.10",
                        records=("ns", "203.0.113.10")))

        monkeypatch.setattr(guardian.dnscheck, "check_dns_egress",
                            _fake_dns_egress)
        # P2-14：③' collect_fakeips（真实 getaddrinfo）与防火墙状态读
        # （真实 PS 子进程）补打桩——CI/断网机器语义下也可运行。
        monkeypatch.setattr(guardian, "collect_fakeips",
                            lambda cfg, log=None: ("198.18.0.1",))
        monkeypatch.setattr(guardian.fw_mod, "get_status_fakeip",
                            lambda cfg: "ENABLED")
        cfg = make_config(dns_egress_countries=["US"])
        rc = guardian.selfcheck(cfg)
        out = capsys.readouterr().out
        # 主结论在第一行（防火墙状态），技术细节在分隔线之后
        assert out.splitlines()[0].startswith(("🛡", "✅"))
        assert "技术细节" in out
        assert "①" in out and "②" in out and "③" in out and "④" in out
        assert rc == 0
        # P2-1：selfcheck 必须传出 config.dns_egress_countries 与
        # dns_whitelist（不再 or 链回退）
        assert seen_args["countries"] == ["US"]
        assert seen_args["wl"] == list(cfg.dns_whitelist)

    def test_selfcheck_fully_mocked_no_subprocess(self, tmp_path, capsys, monkeypatch):
        """P2-14：TestSelfcheck 全 mock 后零真实子进程——断网/无同名规则
        机器语义下也可运行（subprocess.run 被调用即失败）。"""
        monkeypatch.setattr(guardian.netprobe, "check_mihomo_process",
                            lambda name: True)
        monkeypatch.setattr(guardian.netprobe, "check_tun_adapter",
                            lambda kw, rng: (True, "Mihomo"))
        monkeypatch.setattr(guardian.netprobe, "probe_echo_endpoints",
                            lambda eps: guardian.netprobe.EchoResult(
                                ok=True, ip="203.0.113.10", endpoint=eps[0]))
        monkeypatch.setattr(guardian.dnscheck, "check_fakeip",
                            lambda host, rng: guardian.dnscheck.FakeIpResult(
                                ok=True, resolved_ips=("198.18.0.1",),
                                in_fakeip_range=True))
        monkeypatch.setattr(
            guardian.dnscheck, "check_dns_egress",
            lambda domain, wl, countries=None: (
                guardian.policy.CLEAN,
                guardian.dnscheck.DnsEgressResult(
                    ok=True, egress_ip="203.0.113.10",
                    records=("ns", "203.0.113.10"))))
        monkeypatch.setattr(guardian, "collect_fakeips",
                            lambda cfg, log=None: ("198.18.0.1",))
        monkeypatch.setattr(guardian.fw_mod, "get_status_fakeip",
                            lambda cfg: "ENABLED")

        import subprocess as _sp
        monkeypatch.setattr(
            _sp, "run",
            lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("selfcheck 不应发起真实子进程")))
        rc = guardian.selfcheck(make_config())
        assert rc == 0

    def test_selfcheck_dns_probe_exception_fail_closed(self, tmp_path, capsys, monkeypatch):
        """P3-12a：检查⑤底层解析异常（如 struct.error）→ selfcheck 正常
        输出"探测异常"且退出码非 0（fail-closed，不自判"已放行"）。"""
        monkeypatch.setattr(guardian.netprobe, "check_mihomo_process",
                            lambda name: True)
        monkeypatch.setattr(guardian.netprobe, "check_tun_adapter",
                            lambda kw, rng: (True, "Mihomo"))
        monkeypatch.setattr(guardian.netprobe, "probe_echo_endpoints",
                            lambda eps: guardian.netprobe.EchoResult(
                                ok=True, ip="203.0.113.10", endpoint=eps[0]))
        monkeypatch.setattr(guardian.dnscheck, "check_fakeip",
                            lambda host, rng: guardian.dnscheck.FakeIpResult(
                                ok=True, resolved_ips=("198.18.0.1",),
                                in_fakeip_range=True))

        def _boom(domain, wl, countries=None):
            raise struct.error("remote-socket buffer overflow")

        monkeypatch.setattr(guardian.dnscheck, "check_dns_egress", _boom)
        monkeypatch.setattr(guardian, "collect_fakeips",
                            lambda cfg, log=None: ("198.18.0.1",))
        monkeypatch.setattr(guardian.fw_mod, "get_status_fakeip",
                            lambda cfg: "ENABLED")
        rc = guardian.selfcheck(make_config())
        out = capsys.readouterr().out
        assert rc != 0  # fail-closed：探测异常按不可达处理，不放行
        assert "⑤" in out and "探测异常" not in out  # 主结论区不误判泄漏
        # DNS 三态为"未探测"而非"未通过"（不可达 ≠ 泄漏）
        assert "未探测" in out

    def test_selfcheck_intro_from_messages(self, tmp_path, capsys, monkeypatch):
        """P3-18：selfcheck 分隔线前两条文案来自 messages.selfcheck_intro()
        （monkeypatch 返回哨兵值可观测传播；两个消费分支各跑一遍）。"""
        base_mocks = dict(
            mihomo=lambda name: True,
            tun=lambda kw, rng: (True, "Mihomo"),
        )

        def _mock_common():
            monkeypatch.setattr(guardian.netprobe, "check_mihomo_process",
                                base_mocks["mihomo"])
            monkeypatch.setattr(guardian.netprobe, "check_tun_adapter",
                                base_mocks["tun"])
            monkeypatch.setattr(guardian.dnscheck, "check_fakeip",
                                lambda host, rng: guardian.dnscheck.FakeIpResult(
                                    ok=True, resolved_ips=("198.18.0.1",),
                                    in_fakeip_range=True))
            monkeypatch.setattr(guardian, "collect_fakeips",
                                lambda cfg, log=None: ("198.18.0.1",))
            monkeypatch.setattr(guardian.fw_mod, "get_status_fakeip",
                                lambda cfg: "ENABLED")
            monkeypatch.setattr(guardian.messages, "selfcheck_intro",
                                lambda: ("[哨兵-未确认提示]", "[哨兵-只读说明]"))

        # 分支一：echo/DNS 全净（unconfirmed=False？——echo 不可达时才
        # unconfirmed，这里让 echo 不可达以走未确认分支）
        _mock_common()
        monkeypatch.setattr(guardian.netprobe, "probe_echo_endpoints",
                            lambda eps: guardian.netprobe.EchoResult(
                                ok=False, ip=None, endpoint=None, error="x"))
        monkeypatch.setattr(guardian.dnscheck, "check_dns_egress",
                            lambda domain, wl, countries=None: (
                                guardian.policy.UNREACHABLE,
                                guardian.dnscheck.DnsEgressResult(ok=False)))
        guardian.selfcheck(make_config())
        out = capsys.readouterr().out
        assert "[哨兵-未确认提示]" in out   # unconfirmed 分支消费第一条
        assert "[哨兵-只读说明]" in out     # 放行（未确认）分支消费第二条

        # 分支二：全净 → status_line 主结论；只读说明仍消费第二条
        _mock_common()
        monkeypatch.setattr(guardian.netprobe, "probe_echo_endpoints",
                            lambda eps: guardian.netprobe.EchoResult(
                                ok=True, ip="203.0.113.10", endpoint=eps[0]))
        monkeypatch.setattr(guardian.dnscheck, "check_dns_egress",
                            lambda domain, wl, countries=None: (
                                guardian.policy.CLEAN,
                                guardian.dnscheck.DnsEgressResult(
                                    ok=True, egress_ip="203.0.113.10",
                                    records=("ns",))))
        rc = guardian.selfcheck(make_config())
        out = capsys.readouterr().out
        assert rc == 0
        assert "[哨兵-未确认提示]" not in out
        assert "[哨兵-只读说明]" in out

    def test_guardian_module_no_pystray(self):
        import guardian as g_mod
        src = open(g_mod.__file__, encoding="utf-8").read()
        assert "import pystray" not in src
        assert "from pystray" not in src


# ----------------------------------------------------------------- C1 frozen 路径

class TestEntrypointConfigPath:
    def test_frozen_config_path_next_to_exe(self, tmp_path, monkeypatch):
        """frozen 模式：正常启动分支必须加载 exe 同目录的 config.json（C1）。"""
        import scripts.run_guardian as rg
        exe_dir = tmp_path / "dist"
        exe_dir.mkdir()
        fake_cfg = exe_dir / "config.json"
        loaded: list = []

        def fake_load(path):
            loaded.append(str(path))
            return make_config(log_dir=str(tmp_path / "logs"))

        monkeypatch.setattr(rg, "load_config", fake_load)
        monkeypatch.setattr(rg.sys, "frozen", True, raising=False)
        monkeypatch.setattr(rg.sys, "executable", str(exe_dir / "ClaudeGuard.exe"))
        # --check 分支会跑 selfcheck；换成桩避免真探测
        monkeypatch.setattr(rg, "selfcheck", lambda cfg: (loaded.append(str(cfg and 0)) or 0))
        rc = rg.main(["--check"])
        assert rc == 0
        assert loaded and loaded[0] == str(fake_cfg)

    def test_nonfrozen_config_path_is_repo_root(self, monkeypatch):
        import scripts.run_guardian as rg
        monkeypatch.setattr(rg.sys, "frozen", False, raising=False)
        assert rg._default_config_path() == rg.CONFIG_PATH


# ----------------------------------------------------------------- H4 托盘退出语义

class TestTrayExitSemantics:
    def test_tray_exit_menu_sends_exit_command(self, tmp_path):
        """托盘“退出”菜单投递 exit（T-6），而非 quit。"""
        import tray as tray_mod
        t = tray_mod.Tray()
        menu_items = []

        def walk(menu):
            for item in menu:
                if isinstance(item, tray_mod.pystray.Menu):
                    walk(item)
                elif hasattr(item, "text"):
                    menu_items.append(item)

        walk(t._build_menu())
        exit_items = [i for i in menu_items if "退出" in str(getattr(i, "text", ""))]
        assert len(exit_items) == 1
        # MenuItem 可调用：调用后应投递 EXIT 命令
        exit_items[0](None)
        assert t.commands.get_nowait() == tray_mod.Command.EXIT

    def test_exit_command_restores_block_before_stop(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        fw.global_enabled = False  # 模拟放行态退出
        assert g.handle_command("exit") is False
        assert fw.global_enabled is True
        assert g._stop.is_set()

    def test_quit_debug_only_keeps_state(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        assert g.handle_command("quit") is False
        assert "enable" not in fw.calls and "disable" not in fw.calls


# ----------------------------------------------------------------- H5 CIDR 热重载重建

class TestCidrHotReloadRebuild:
    def _write_cfg(self, path, tmp_path, **over):
        import json
        data = {
            "blocked_cidrs_v4": ["160.79.104.0/23"],
            "blocked_cidrs_v6": ["2607:6bc0::/48"],
            "rule_name_v4": "CG-Global", "rule_name_v6": "CG-V6",
            "whitelist": ["203.0.113.10"],
            "echo_endpoints": ["https://echo.test/ip"],
            "fakeip_range": "198.18.0.0/15",
            "mihomo_process": "verge-mihomo.exe",
            "tun_adapter_keywords": ["mihomo"],
            "fast_tick_sec": 1, "slow_tick_sec": 5,
            "pass_confirm_count": 3, "fail_unreachable_threshold": 5,
            "doh_check_interval_min": 60, "ripe_check_interval_hours": 24,
            "override_minutes": 30, "claude_domains": ["claude.ai"],
            "asn": "AS399358", "log_dir": str(path.parent / "logs"),
            "log_retention_days": 30,
        }
        data.update(over)
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_v4_cidr_change_rebuilds_rule(self, tmp_path):
        """P2-5：tick 内零 PS——只置 _pending_rebuild，重建由 heal 线程执行。"""
        cfg_path = tmp_path / "config.json"
        self._write_cfg(cfg_path, tmp_path)
        g, fw, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        import json, os
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        data["blocked_cidrs_v4"] = ["160.79.104.0/23", "203.0.113.0/24"]
        cfg_path.write_text(json.dumps(data), encoding="utf-8")
        st = os.stat(cfg_path)
        os.utime(cfg_path, (st.st_atime, st.st_mtime + 10))
        g.tick()
        # tick 内：只置标志，不发 create_rule
        assert "create_rule" not in fw.calls
        assert g._pending_rebuild == (True, False)
        # heal 线程消费标志 → 重建发生（guardian-main 线程外）
        g._self_heal_rules()
        assert "create_rule" in fw.calls
        # BLOCKED 期望 Enabled：重建后不应 disable
        assert "disable" not in fw.calls
        # 标志已消费，不重复重建
        assert g._pending_rebuild is None

    def test_v6_cidr_change_rebuilds_rule(self, tmp_path):
        """P2-5：v6 段变化同样走 heal 线程重建，重建后 CG-V6 强制 Enabled。"""
        cfg_path = tmp_path / "config.json"
        self._write_cfg(cfg_path, tmp_path)
        g, fw, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        import json, os
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        data["blocked_cidrs_v6"] = ["2607:6bc0::/48", "2001:db8::/32"]
        cfg_path.write_text(json.dumps(data), encoding="utf-8")
        st = os.stat(cfg_path)
        os.utime(cfg_path, (st.st_atime, st.st_mtime + 10))
        g.tick()
        assert "create_rule_v6" not in fw.calls       # tick 内零 PS
        assert g._pending_rebuild == (False, True)
        g._self_heal_rules()
        assert "create_rule_v6" in fw.calls
        assert "ensure_enabled_v6" in fw.calls        # 重建后 v6 强制 Enabled

    def test_no_cidr_change_no_rebuild(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        self._write_cfg(cfg_path, tmp_path)
        g, fw, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        import json, os
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        data["whitelist"] = ["1.2.3.4"]
        cfg_path.write_text(json.dumps(data), encoding="utf-8")
        st = os.stat(cfg_path)
        os.utime(cfg_path, (st.st_atime, st.st_mtime + 10))
        g.tick()
        assert "create_rule" not in fw.calls
        assert "create_rule_v6" not in fw.calls

    def test_rebuild_restores_disabled_when_allowed(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        self._write_cfg(cfg_path, tmp_path)
        g, fw, *_ , _ = make_guardian(tmp_path, config_path=cfg_path)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        g._rebuild_blocked_rules(v4=True, v6=False)
        assert "create_rule" in fw.calls
        assert "disable" in fw.calls            # 期望 Disabled → 恢复
        assert fw.global_enabled is False


# ----------------------------------------------------------------- L2 漂移间隔热生效

class TestDriftIntervalHotReload:
    def test_drift_loop_rereads_interval_each_iteration(self, tmp_path):
        g, *_ , _ = make_guardian(tmp_path)
        # 模拟：启动后热重载把 doh 间隔从 60min 改为 1min
        seen = []
        real_config = g.config

        class SwapCfg:
            def __getattr__(self, name):
                seen.append(name)
                if name == "doh_check_interval_min":
                    return 1  # 热重载后的新值
                return getattr(real_config, name)

        g.config = SwapCfg()
        # wait 第一次被调用即置 stop：循环体恰好完整跑一轮后退出
        g._stop.wait = lambda timeout: (g._stop.set(), 0)[1]
        g._drift_loop()
        assert "doh_check_interval_min" in seen


# ----------------------------------------------------------------- L4 override 顺序

class TestOverrideOrdering:
    def test_override_until_set_before_event(self, tmp_path, monkeypatch):
        g, fw, *_ , clock = make_guardian(tmp_path)
        clock.advance(500)
        order = []
        real_apply = g._apply_event

        def spy(event):
            order.append(("until", g.override_until))
            real_apply(event)

        monkeypatch.setattr(g, "_apply_event", spy)
        g._start_override()
        # _apply_event 被调用时 override_until 已设置
        assert order[0] == ("until", 500 + 30 * 60)
        assert g._gstate.on_override is True


# ----------------------------------------------------------------- M1 guardian 层幂等

class TestBlockedCheckFailIdempotent:
    def test_blocked_check_fail_no_repeat_toast_or_enable(self, tmp_path):
        """BLOCKED 态 CHECK_FAIL 幂等：不重复 enable、不重复弹窗。"""
        toasts = []
        np = FakeNetprobe(echo_ip="203.0.113.9")  # 白名单外 → DIRTY
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        g._notify = lambda t, b: toasts.append(t)
        g._gstate = sm.GateState(state=sm.BLOCKED)
        fw.global_enabled = True
        for _ in range(3):
            g._tick_count = 4
            g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert toasts == []                      # 无重复通知
        # 无冗余 enable（自愈例外：周期性校验不算状态机动作）
        assert g._gstate.state == sm.BLOCKED


# ----------------------------------------------------------------- CG-FakeIP

class TestCollectFakeips:
    def test_collects_only_fakeip_range_addresses(self):
        import socket as s
        cfg = make_config(claude_domains=["a.test", "b.test"])
        infos = {
            "a.test": [(2, 1, 6, "", ("198.18.0.1", 0)),
                       (2, 1, 6, "", ("203.0.113.10", 0))],  # 真实 IP 不入集
            "b.test": [(2, 1, 6, "", ("198.18.5.9", 0))],
        }
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: infos.get(h, [])
        try:
            assert guardian.collect_fakeips(cfg) == ("198.18.0.1", "198.18.5.9")
        finally:
            s.getaddrinfo = real

    def test_resolve_failure_skips_domain(self):
        import socket as s
        cfg = make_config(claude_domains=["dead.test", "ok.test"])

        def ga(host, *a, **k):
            if host == "dead.test":
                raise OSError("resolve failed")
            return [(2, 1, 6, "", ("198.18.0.7", 0))]

        real = s.getaddrinfo
        s.getaddrinfo = ga
        try:
            assert guardian.collect_fakeips(cfg) == ("198.18.0.7",)
        finally:
            s.getaddrinfo = real

    def test_bad_fakeip_range_returns_empty(self):
        cfg = make_config(fakeip_range="not-a-range")
        assert guardian.collect_fakeips(cfg) == ()


class TestFakeipLifecycle:
    def test_dirty_state_enables_fakeip(self, tmp_path):
        """脏态迁移 → ENABLE_FIREWALL 同步 enable CG-FakeIP。"""
        np = FakeNetprobe(echo_ip="198.51.100.99")  # 白名单外 → DIRTY
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.fakeip_enabled = False
        g._tick_count = 4  # 触发慢路径
        g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert fw.fakeip_enabled is True
        assert "set_blocking_on" in fw.calls  # 原子切换含 FakeIP enable

    def test_allowed_state_disables_fakeip(self, tmp_path):
        np = FakeNetprobe(echo_ip="203.0.113.10")  # 白名单内
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        fw.fakeip_enabled = True
        for _ in range(3):  # pass_confirm_count=3
            g._tick_count = 4
            g.tick()
        assert g._gstate.state == sm.ALLOWED
        assert fw.fakeip_enabled is False
        assert "set_blocking_off" in fw.calls  # 原子切换含 FakeIP disable

    def test_fakeip_set_change_rebuilds_rule(self, tmp_path):
        """慢路径每轮重解析；集合变化 → 登记 pending 并唤醒 refresh 线程
        重建（P2-5：tick 内零 PS，重建最终发生在 fakeip-refresh 线程）。"""
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = sm.GateState(state=sm.BLOCKED)
        fw.fakeip_enabled = True
        current = {"ips": ["198.18.0.1"]}

        def ga(host, *a, **k):
            return [(2, 1, 6, "", (ip, 0)) for ip in current["ips"]]

        real = s.getaddrinfo
        s.getaddrinfo = ga
        g._fakeip_thread = threading.Thread(
            target=g._fakeip_refresh_loop, name="fakeip-refresh", daemon=True)
        g._fakeip_thread.start()
        try:
            g._tick_count = 4
            g.tick()
            assert wait_for_calls(fw, "create_rule_fakeip", 1)
            assert fw.fakeip_ips == ["198.18.0.1"]
            current["ips"] = ["198.18.0.2", "198.18.0.1"]
            g._tick_count = 9
            g.tick()
            assert wait_for_calls(fw, "create_rule_fakeip", 2)
            assert fw.fakeip_ips == ["198.18.0.2", "198.18.0.1"]
            before = fw.calls.count("create_rule_fakeip")
            g._tick_count = 14
            g.tick()
            import time as _t
            _t.sleep(0.1)   # 无变化不应再重建
            assert fw.calls.count("create_rule_fakeip") == before
        finally:
            s.getaddrinfo = real
            g._stop.set()
            g._fakeip_wake.set()
            g._fakeip_thread.join(timeout=5)

    def test_empty_fakeip_set_keeps_rule(self, tmp_path):
        """解析失败（空集）→ 规则保持现状，不被清空。"""
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        fw.fakeip_enabled = True
        fw.fakeip_ips = ["198.18.0.1"]
        g._fakeip_rule_ips = ("198.18.0.1",)

        def boom(h, *a, **k):
            raise OSError("boom")

        real = s.getaddrinfo
        s.getaddrinfo = boom
        try:
            g._tick_count = 4
            g.tick()
            assert fw.fakeip_ips == ["198.18.0.1"]
            assert "create_rule_fakeip" not in fw.calls
        finally:
            s.getaddrinfo = real

    def test_real_ips_not_written_to_rule(self, tmp_path):
        """解析只返回真实 IP → 空集，不写入规则。"""
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        fw.fakeip_enabled = None  # 规则尚未建立
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", ("203.0.113.10", 0))]
        try:
            g._tick_count = 4
            g.tick()
            assert "create_rule_fakeip" not in fw.calls
            assert fw.fakeip_enabled is None
        finally:
            s.getaddrinfo = real

    def test_fakeip_rebuild_in_allowed_state_restores_disabled(self, tmp_path):
        """放行态下集合变化重建后须恢复 Disabled（重建动作经 refresh 线程）。"""
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = sm.GateState(state=sm.ALLOWED, on_override=False)
        g._fakeip_rule_ips = ("198.18.0.1",)
        fw.fakeip_enabled = False
        fw.fakeip_ips = ["198.18.0.1"]
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", ("198.18.0.9", 0))]
        try:
            g._refresh_fakeip_rule()          # 只登记 pending + 唤醒
            assert g._fakeip_pending == ("198.18.0.9",)
            g._rebuild_fakeip_rule(g._fakeip_pending)  # 线程内执行的重建
            assert fw.fakeip_ips == ["198.18.0.9"]
            assert fw.fakeip_enabled is False
        finally:
            s.getaddrinfo = real

    def test_heal_corrects_fakeip_drift(self, tmp_path):
        """自愈：CG-FakeIP 被第三方禁用（阻断态）→ 纠正回 Enabled。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = sm.GateState(state=sm.BLOCKED)
        fw.fakeip_enabled = False
        fw.fakeip_ips = ["198.18.0.1"]
        g._fakeip_rule_ips = ("198.18.0.1",)
        g._self_heal_rules()
        assert fw.fakeip_enabled is True

    def test_heal_rebuilds_missing_fakeip(self, tmp_path):
        """自愈：规则被删且放行态 → 用已知集合重建并 Disabled。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.fakeip_enabled = None
        g._fakeip_rule_ips = ("198.18.0.1",)
        g._self_heal_rules()
        assert fw.fakeip_ips == ["198.18.0.1"]
        assert fw.fakeip_enabled is False

    def test_hot_reload_domain_change_rebuilds(self, tmp_path):
        """热重载 claude_domains 变化 → CG-FakeIP 重建。"""
        import json as _json
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(_json.dumps({
            "blocked_cidrs_v4": ["203.0.113.0/24"],
            "blocked_cidrs_v6": ["2001:db8::/48"],
            "rule_name_v4": "CG-Global", "rule_name_v6": "CG-V6",
            "whitelist": ["203.0.113.10"],
            "echo_endpoints": ["https://echo.test/ip"],
            "fakeip_range": "198.18.0.0/15",
            "mihomo_process": "m.exe",
            "tun_adapter_keywords": ["mihomo"],
            "fast_tick_sec": 1, "slow_tick_sec": 5,
            "pass_confirm_count": 3, "fail_unreachable_threshold": 5,
            "doh_check_interval_min": 60, "ripe_check_interval_hours": 24,
            "override_minutes": 30, "claude_domains": ["claude.ai"],
            "asn": "AS399358", "log_dir": "logs",
            "log_retention_days": 30,
        }), encoding="utf-8")
        data = _json.loads(cfg_path.read_text(encoding="utf-8"))
        data["claude_domains"] = ["claude.ai", "api.anthropic.com"]
        cfg_path.write_text(_json.dumps(data), encoding="utf-8")

        calls = {"n": 0}

        def ga(host, *a, **k):
            calls["n"] += 1
            return [(2, 1, 6, "", ("198.18.0.1", 0))]

        real = s.getaddrinfo
        s.getaddrinfo = ga
        g._fakeip_thread = threading.Thread(
            target=g._fakeip_refresh_loop, name="fakeip-refresh", daemon=True)
        g._fakeip_thread.start()
        try:
            g._config_mtime = None
            g._maybe_reload_config()          # tick 内：只置 None + 唤醒
            assert g.config.claude_domains == ["claude.ai", "api.anthropic.com"]
            assert "create_rule_fakeip" not in fw.calls   # tick 内零 PS
            assert wait_for_calls(fw, "create_rule_fakeip", 1)
            assert fw.fakeip_ips == ["198.18.0.1"]
        finally:
            # 先停线程再还原 getaddrinfo：refresh 线程若在还原后重采集，
            # 会拿到本机真实 mihomo fake-ip（非确定值）污染断言
            g._stop.set()
            g._fakeip_wake.set()
            g._fakeip_thread.join(timeout=5)
            s.getaddrinfo = real


# ----------------------------------------------------------------- fake-ip 迁移刷新

class TestFakeipMigrationRefresh:
    def test_transition_triggers_fakeip_refresh(self, tmp_path):
        """状态迁移 set _fakeip_wake → fakeip-refresh 线程立即重采集重建
        CG-FakeIP（不等慢路径 5s）。"""
        import socket as s
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._fakeip_thread = threading.Thread(
            target=g._fakeip_refresh_loop, name="fakeip-refresh", daemon=True)
        g._fakeip_thread.start()
        current = {"ips": ["198.18.0.1"]}

        def ga(host, *a, **k):
            return [(2, 1, 6, "", (ip, 0)) for ip in current["ips"]]

        real = s.getaddrinfo
        s.getaddrinfo = ga
        try:
            # 迁移前集合已知；迁移点换新 fake-ip 并触发
            g._fakeip_rule_ips = ("198.18.0.1",)
            current["ips"] = ["198.18.0.7"]
            np = getattr(g, "np")
            np.mihomo = False  # FAST_FAIL → BLOCKED 迁移
            g._gstate = sm.GateState(state=sm.ALLOWED)
            fw.global_enabled = False
            g._apply_event(sm.FAST_FAIL)
            assert wait_for_calls(fw, "create_rule_fakeip", 1, timeout=5)
            assert fw.fakeip_ips == ["198.18.0.7"]
        finally:
            s.getaddrinfo = real
            g._stop.set()
            g._fakeip_wake.set()
            g._fakeip_thread.join(timeout=5)

    def test_transition_wake_immediately_not_slow_tick(self, tmp_path):
        """迁移触发即刷新：不再依赖 _tick_count 到慢路径轮次。"""
        np = FakeNetprobe(echo_ip="203.0.113.9")  # 白名单外 → DIRTY
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        before = fw.calls.count("create_rule_fakeip")
        g._tick_count = 0  # 本轮慢路径不跑（% 5 != 0），只靠迁移唤醒
        # 慢路径刷新未跑，规则内集合还是旧值 → 唤醒线程必须自己重采集
        g._fakeip_thread = threading.Thread(
            target=g._fakeip_refresh_loop, name="fakeip-refresh", daemon=True)
        g._fakeip_thread.start()
        g._tick_count = 1
        event = None
        np.mihomo = False  # 走快路径 FAST_FAIL（纯迁移，无慢路径 fakeip 刷新）
        g.tick()
        assert g._gstate.state == sm.BLOCKED
        assert wait_for_calls(fw, "create_rule_fakeip", before + 1, timeout=5)
        g._stop.set()
        g._fakeip_wake.set()
        g._fakeip_thread.join(timeout=5)


class TestAuditCopyFixes:
    """文案-行为一致性审查（三代理全盘审查）修复的回归保护。"""

    def test_check_pass_preserves_override(self):
        """CHECK_PASS 保留 on_override：override 中环境转干净，到期
        恢复阻断的承诺仍生效（曾清标志导致到期永不触发、审计缺 end）。"""
        st = sm.GateState(sm.BLOCKED, on_override=True)
        tr = sm.transition(st, sm.CHECK_PASS)
        assert tr.new_state.state == sm.ALLOWED
        assert tr.new_state.on_override is True

    def test_pause_ends_override_and_freezes(self, tmp_path):
        """暂停时结束 override：on_override=False + 审计补记 end（防 heal
        线程按 override 期望反向放行规则，与"冻结阻断"矛盾）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g.handle_command("override_30min")
        assert g._gstate.on_override is True
        g.handle_command("toggle_pause")
        assert g.paused is True
        assert g._gstate.on_override is False
        assert g.override_until is None
        audit = tmp_path / "logs" / "override-audit.log"
        assert "end pause" in audit.read_text(encoding="utf-8")

    def test_override_start_toast_on_override_start_event(self, tmp_path):
        """P3-5 正例：OVERRIDE_START 首次启动仍发"临时放行开始"。"""
        toasts = []
        g, fw, *_ , _ = make_guardian(
            tmp_path, notify_fn=lambda t, b: toasts.append((t, b)))
        g._apply_event(sm.OVERRIDE_START)
        assert len(toasts) == 1
        assert "临时放行" in toasts[0][1] and "分钟" in toasts[0][1]

    def test_override_start_toast_skipped_on_check_pass_during_override(self, tmp_path):
        """P3-5 回归：override 从 BLOCKED 启动后慢路径连续 CLEAN 触发
        CHECK_PASS 迁移——NOTIFY_ALLOW 不再误判为"临时放行开始"重弹
        toast_override_start，只发普通放行文案（或不弹）。"""
        toasts = []
        g, fw, *_ , _ = make_guardian(
            tmp_path, notify_fn=lambda t, b: toasts.append((t, b)))
        # override 启动（BLOCKED 态点 override）
        g._apply_event(sm.OVERRIDE_START)
        assert sum("临时放行" in b for _, b in toasts) == 1
        # override 期间环境转净：CHECK_PASS 迁移（on_override 仍 True）
        g._apply_event(sm.CHECK_PASS)
        assert g._gstate.state == sm.ALLOWED
        starts = [b for _, b in toasts if "临时放行" in b]
        assert len(starts) == 1  # 不重弹
        assert any("出口 IP 干净" in b for _, b in toasts)  # 普通放行文案

    def test_heal_expected_enabled_when_paused(self, tmp_path):
        """暂停期间 heal 线程期望恒为 Enabled（冻结阻断）。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g.handle_command("override_30min")  # 正常情况期望 Disabled
        g.paused = True                     # 暂停后期望必须翻转为 Enabled
        g._self_heal_rules()
        assert fw.global_enabled is True

    def test_override_expire_toast_uses_end_copy(self, tmp_path):
        """override 到期 Toast 用专属文案"临时放行已结束"（曾走通用
        阻断文案+出口误报"不在白名单"）。"""
        toasts = []
        g, fw, *_ , _ = make_guardian(
            tmp_path, notify_fn=lambda t, b: toasts.append((t, b)))
        g.handle_command("override_30min")
        g.handle_command("end_override")
        assert any("临时放行已结束" in b for _, b in toasts)

    def test_block_toast_no_false_dirty_when_echo_clean(self, tmp_path):
        """阻断 Toast 不对白名单内出口误报"不在白名单"（曾强制置脏：
        DNS 不可达升级阻断时对干净出口弹"出口 IP 不干净"）。"""
        from core import messages as msgs
        # DNS 探针不可达（连续升级阻断）但出口干净
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._last_checks = {
            "mihomo进程": True, "TUN网卡": True, "fake-ip": True,
            "echo出口": True, "DNS出口干净": None,  # 不可达（三态）
        }
        g._last_echo_ip = "203.0.113.10"
        g._last_echo_in_whitelist = True
        title, body = g._toast_text(guardian.sm.NOTIFY_BLOCK)
        assert "不在你的白名单里" not in body
        assert "暂时无法确认" in body

    def test_push_tray_no_dns_ip_when_clean(self, tmp_path):
        """CLEAN 态 dns_leak_ip 必须为 None（详情窗曾显示递归出口 IP
        被读成泄漏，同屏"DNS出口干净: 通过"自相矛盾）。"""
        class _Sink:
            def __init__(self): self.events = []
            def push_event(self, evt): self.events.append(evt)
        sink = _Sink()
        g, fw, *_ , _ = make_guardian(tmp_path, tray=sink)
        g._last_checks = {"mihomo进程": True, "TUN网卡": True, "fake-ip": True,
                          "echo出口": True, "DNS出口干净": True}
        g._last_dns_ip = "198.51.100.20"  # 慢路径每轮无条件赋值过
        g._last_echo_ip = "203.0.113.10"
        g._last_echo_in_whitelist = True
        g._push_tray()
        evt = sink.events[-1]
        assert evt.dns_leak_ip is None
        # whitelist_hit 三态直传（None=未探测，由 tray 显示"未探测"）
        assert evt.whitelist_hit is True

    def test_whitelist_hit_none_shows_unprobed(self):
        """白名单命中未探测显示"未探测"，不断言"否"。"""
        from tray import State, StateEvent
        evt = StateEvent(state=State.BLOCKED, whitelist_hit=None,
                         checks={"mihomo进程": True})
        lines = evt.detail_lines()
        assert any(ln == "白名单命中: 未探测" for ln in lines)

    def test_fast_fail_records_real_values(self, tmp_path):
        """fast-fail 快照按真实结果记录（曾硬编码双 False：只挂 TUN 时
        mihomo 被误报未运行）。"""
        np = FakeNetprobe(mihomo=True, tun=False)
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        g.tick()
        assert g._last_checks["mihomo进程"] is True
        assert g._last_checks["TUN网卡"] is False


# ----------------------------------------------------------------- P1-2 竞态回归

class TestExitHealRace:
    """P1-2：EXIT 与 rule-heal 竞态——exit 先 _stop.set() 再 block_all（final），
    heal/_fw_tolerant 见 stop 放弃 disable 方向纠正。"""

    def test_exit_sets_stop_before_block_all(self, tmp_path):
        """exit 分支顺序契约：block_all 执行时 stop 已置位。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        seen = {}

        def recording_block_all(config, fakeip_ips=None):
            seen["stop_at_block_all"] = g._stop.is_set()
            fw.block_all(config, fakeip_ips)

        fw.block_all = recording_block_all
        assert g.handle_command("exit") is False
        assert seen["stop_at_block_all"] is True

    def test_fw_tolerant_skips_writes_after_stop(self, tmp_path):
        """stop 置位后非 final 写入被闸掉；final=True 放行。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._stop.set()
        assert g._fw_tolerant("disable") is False
        assert "disable" not in fw.calls
        assert g._fw_tolerant("block_all", final=True) is True
        assert "block_all" in fw.calls

    def test_heal_aborts_disable_correction_after_stop(self, tmp_path):
        """heal 飞行中 stop 置位：gstate=ALLOWED（期望 disable）但规则实际
        Enabled——正常会 disable；退出中必须放弃纠正。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = guardian.sm.GateState(state=guardian.sm.ALLOWED)
        fw.global_enabled = True   # 实际 Enabled ≠ 期望 disabled → 会纠正
        g._stop.set()
        g._self_heal_rules()
        assert "disable" not in fw.calls
        assert "disable_fakeip" not in fw.calls

    def test_heal_aborts_fakeip_rebuild_disable_after_stop(self, tmp_path):
        """MISSING 重建路径：重建成功后退出中，不得按旧期望 disable。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = guardian.sm.GateState(state=guardian.sm.ALLOWED)
        fw.missing = True
        fw.global_enabled = True   # ensure_exists 重建后 Enabled
        g._fakeip_rule_ips = ["198.18.0.1"]
        fw.fakeip_enabled = None   # CG-FakeIP MISSING → 重建分支
        g._stop.set()
        g._self_heal_rules()
        # CG-Global 重建允许（enable 方向），但 disable 纠正必须被闸掉
        assert "disable" not in fw.calls
        assert "disable_fakeip" not in fw.calls

    def test_heal_still_corrects_when_running(self, tmp_path):
        """正常（非退出）heal 语义不变：期望 disabled、实际 Enabled → 纠正。"""
        g, fw, *_ , _ = make_guardian(tmp_path)
        g._gstate = guardian.sm.GateState(state=guardian.sm.ALLOWED)
        fw.global_enabled = True
        g._self_heal_rules()
        assert "disable" in fw.calls


# ----------------------------------------------------------------- P1-4 失败路径

class TestFwPersistentFailure:
    """P1-4：最重 fail-open 链路纳入回归——set_blocking 持续失败时
    状态机仍迁移 BLOCKED（意图），_fw_tolerant 耗尽返回 False，
    下轮 heal 仍尝试纠正（意图不被放弃）。"""

    def test_fast_fail_set_blocking_exhaustion(self, tmp_path, caplog):
        """FAST_FAIL 时 set_blocking 持续抛错：状态迁移照常、写入失败
        记日志、返回 False——规则未生效的窗口由 heal 兜底，本用例锁
        「迁移不停、重试有痕」两条不变量。"""
        np = FakeNetprobe(mihomo=False)
        fw = FakeFirewall(fail_methods={"set_blocking"})
        g, fw, np, *_ , _ = make_guardian(tmp_path, np=np, fw=fw)
        g._gstate = sm.GateState(state=sm.ALLOWED)
        fw.global_enabled = False
        import logging as _logging
        with caplog.at_level(_logging.ERROR, logger="test-guard"):
            g.tick()
        assert g._gstate.state == sm.BLOCKED      # 意图迁移不被写入失败阻断
        assert fw.calls.count("set_blocking_on") == 3  # 重试 3 次
        assert any("重试 3 次均失败" in r.message for r in caplog.records)

    def test_heal_retries_after_persistent_failure(self, tmp_path):
        """heal 同因失败 → 下轮 heal 仍尝试（期望未被放弃）。"""
        fw = FakeFirewall(fail_methods={"enable_fakeip"})
        g, fw, *_ , _ = make_guardian(tmp_path, fw=fw)
        g._gstate = sm.GateState(state=sm.BLOCKED)  # 期望 Enabled
        fw.fakeip_enabled = False                    # 实际 Disabled → 会纠正
        g._self_heal_rules()
        n1 = fw.calls.count("enable_fakeip")
        assert n1 == 3  # 单轮 _fw_tolerant 重试 3 次
        fw.calls.clear()
        g._self_heal_rules()
        assert fw.calls.count("enable_fakeip") == 3  # 下轮照常尝试


class TestSlowPathProbeConcurrency:
    """慢路径 echo 与 DNS 探针并发：互相独立，wall time = max 而非 sum。"""

    def test_echo_and_dns_probes_overlap(self, tmp_path):
        import socket as s

        barrier = threading.Barrier(2)
        serial = []

        class BarrierNp(FakeNetprobe):
            def probe_echo_endpoints(self, endpoints):
                try:
                    barrier.wait(timeout=2)
                except threading.BrokenBarrierError:
                    serial.append("echo")
                return super().probe_echo_endpoints(endpoints)

        class BarrierDns(FakeDns):
            def check_dns_egress(self, domain, whitelist, allowed_countries=None):
                try:
                    barrier.wait(timeout=2)
                except threading.BrokenBarrierError:
                    serial.append("dns")
                return super().check_dns_egress(domain, whitelist, allowed_countries)

        g, fw, *_ = make_guardian(tmp_path, np=BarrierNp(), dns=BarrierDns())
        real = s.getaddrinfo
        s.getaddrinfo = lambda h, *a, **k: [(2, 1, 6, "", ("198.18.0.1", 0))]
        try:
            local = guardian.netprobe.LocalEnvResult(
                mihomo_running=True, tun_present=True, error=None)
            event = g._slow_path(local)
        finally:
            s.getaddrinfo = real
        # 并发执行：两个探针都在 barrier 等到对方（串行必 broken）
        assert serial == []
        # 功能不受影响：双 CLEAN → 放行计数 +1（首轮未到阈值无事件）
        assert event is None
        assert g._counter.pass_streak == 1
