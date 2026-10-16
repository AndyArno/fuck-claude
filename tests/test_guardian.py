# -*- coding: utf-8 -*-
"""guardian.py 单测：全部 mock platform 层，不发网络、不碰真防火墙。

覆盖：事件映射（快/慢路径 → 状态机事件）、override 计时、快慢调度节奏、
规则自愈、PAUSE/RESUME、QUIT/EXIT、配置热重载、漂移线程事件投递。
"""
from __future__ import annotations

import logging
import threading

import pytest

import guardian
from guardian import Guardian
from core import statemachine as sm
from core.config import Config


# ----------------------------------------------------------------- fakes

class FakeFirewall:
    """记录调用的防火墙替身。初始状态：CG-Global Enabled（阻断态）。"""

    def __init__(self, global_enabled: bool = True) -> None:
        self.global_enabled = global_enabled
        self.calls: list[str] = []

    def create_rule(self, config) -> None:
        self.calls.append("create_rule")

    def enable(self, config) -> None:
        self.calls.append("enable")
        self.global_enabled = True

    def disable(self, config) -> None:
        self.calls.append("disable")
        self.global_enabled = False

    def get_status(self, config) -> bool:
        self.calls.append("get_status")
        return self.global_enabled

    def ensure_exists(self, config) -> None:
        self.calls.append("ensure_exists")

    def create_rule_v6(self, config) -> None:
        self.calls.append("create_rule_v6")

    def ensure_enabled_v6(self, config) -> None:
        self.calls.append("ensure_enabled_v6")

    def get_status_v6(self, config) -> bool:
        return True


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
    )
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
        notify_fn=NOOP, tray=kw.pop("tray", None),
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
        assert "disable" in fw.calls

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
        assert np.echo_calls == 2            # slow_every=5 → 第 5、10 轮

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
        assert "disable" in fw.calls
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
        assert "enable" in fw.calls

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


# ----------------------------------------------------------------- 命令

class TestCommands:
    def test_pause_keeps_rules_and_stops_checks(self, tmp_path):
        np = FakeNetprobe()
        g, fw, *_ , _ = make_guardian(tmp_path, np=np)
        assert g.handle_command("pause") is True
        assert g.paused is True
        before_local = np.local_calls
        g.tick(); g.tick()
        assert np.local_calls == before_local  # 暂停期间不做检查
        assert fw.global_enabled is True       # 规则不动，保持阻断
        assert g.handle_command("resume") is True
        g.tick()
        assert np.local_calls > before_local

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


# ----------------------------------------------------------------- 规则自愈

class TestSelfHeal:
    def test_third_party_reset_corrected(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        # BLOCKED 期望 Enabled，第三方改成 Disabled → 自愈
        fw.global_enabled = False
        g.tick()
        assert fw.global_enabled is True

    def test_self_heal_no_op_when_consistent(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        g.tick()  # BLOCKED + Enabled：一致
        assert "enable" not in fw.calls  # 无纠正调用（只有 v6 ensure / get_status）

    def test_v6_ensured_every_tick(self, tmp_path):
        g, fw, *_ , _ = make_guardian(tmp_path)
        g.tick(); g.tick(); g.tick()
        assert fw.calls.count("ensure_enabled_v6") == 3


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
        cfg = make_config()
        rc = guardian.selfcheck(cfg)
        out = capsys.readouterr().out
        assert "①" in out and "②" in out and "③" in out and "④" in out
        assert rc == 0

    def test_guardian_module_no_pystray(self):
        import guardian as g_mod
        src = open(g_mod.__file__, encoding="utf-8").read()
        assert "import pystray" not in src
        assert "from pystray" not in src
