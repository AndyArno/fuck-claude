# -*- coding: utf-8 -*-
"""DNS 出口探针（检查⑤）测试：TXT 解析纯函数 + guardian 三态接入。"""
import logging

import pytest

import guardian
from core import policy
from winplat import dnscheck


# --------------------------------------------------------------- TXT 解析

class TestParseTxtRecords:
    def test_plain_strings(self):
        assert dnscheck.parse_txt_records(["ns", "198.51.100.20"]) == \
            ("ns", "198.51.100.20")

    def test_strips_quotes_and_spaces(self):
        assert dnscheck.parse_txt_records(['"ns 198.51.100.20"']) == \
            ("ns 198.51.100.20",)

    def test_drops_empty_and_none(self):
        assert dnscheck.parse_txt_records(["", "  ", None, '"x"']) == ("x",)

    def test_empty_input(self):
        assert dnscheck.parse_txt_records([]) == ()

    def test_garbage_kept_as_text(self):
        assert dnscheck.parse_txt_records(["\xff\xfe 乱码"]) == ("\xff\xfe 乱码",)


class TestParseEgressIp:
    def test_ns_then_ip_tokens(self):
        assert dnscheck.parse_egress_ip(("ns", "198.51.100.20")) == \
            "198.51.100.20"

    def test_combined_string(self):
        assert dnscheck.parse_egress_ip(("ns 198.51.100.20",)) == \
            "198.51.100.20"

    def test_ip_only(self):
        assert dnscheck.parse_egress_ip(("203.0.113.9",)) == "203.0.113.9"

    def test_ipv6(self):
        assert dnscheck.parse_egress_ip(("ns 2606:4700:4700::1111",)) == \
            "2606:4700:4700::1111"

    def test_no_ip(self):
        assert dnscheck.parse_egress_ip(("ns", "no-address-here")) is None

    def test_empty(self):
        assert dnscheck.parse_egress_ip(()) is None

    def test_garbage(self):
        assert dnscheck.parse_egress_ip(("\x00\x01garbage", "###")) is None


# ------------------------------------------------------- check_dns_egress

def _patch_query(monkeypatch, result):
    monkeypatch.setattr(dnscheck, "query_txt_windows", lambda host: result)


class TestCheckDnsEgress:
    def test_clean(self, monkeypatch):
        _patch_query(monkeypatch, dnscheck.DnsEgressResult(
            ok=True, egress_ip="203.0.113.10", records=("ns", "203.0.113.10")))
        verdict, probe = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.10"])
        assert verdict == policy.CLEAN
        assert probe.egress_ip == "203.0.113.10"

    def test_dirty(self, monkeypatch):
        _patch_query(monkeypatch, dnscheck.DnsEgressResult(
            ok=True, egress_ip="198.51.100.20", records=("ns",)))
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.10"])
        assert verdict == policy.DIRTY

    def test_dirty_when_no_ip_in_answer(self, monkeypatch):
        # 看到了回答但拿不到 IP → 无法证明干净 → fail-closed
        _patch_query(monkeypatch, dnscheck.DnsEgressResult(
            ok=True, egress_ip=None, records=("ns",)))
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.10"])
        assert verdict == policy.DIRTY

    def test_unreachable(self, monkeypatch):
        _patch_query(monkeypatch, dnscheck.DnsEgressResult(
            ok=False, error="DnsQuery_W status=9003"))
        verdict, probe = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.10"])
        assert verdict == policy.UNREACHABLE
        assert probe.ok is False

    def test_cidr_whitelist(self, monkeypatch):
        _patch_query(monkeypatch, dnscheck.DnsEgressResult(
            ok=True, egress_ip="203.0.113.5"))
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/24"])
        assert verdict == policy.CLEAN


# ------------------------------------------------- guardian 慢路径接入

def _slow_tick(g, tick_count=4):
    """推进到慢路径轮并跑一次 tick。"""
    g._tick_count = tick_count  # slow_every=5 → 第 5 轮（%5==0）走慢路径
    g.tick()


class TestGuardianDnsEgress:
    def _make_dns(self, egress_ip="203.0.113.10", ok=True):
        import tests.test_guardian as guardian_tests
        d = guardian_tests.FakeDns()
        d.egress = dnscheck.DnsEgressResult(
            ok=ok, egress_ip=egress_ip if ok else None,
            records=("ns",) if ok else (),
            error=None if ok else "timeout")
        d.check_dns_egress = lambda domain, wl: (
            (policy.CLEAN if (ok and egress_ip and egress_ip in wl)
             else (policy.UNREACHABLE if not ok else policy.DIRTY)),
            d.egress)
        return d

    def test_dns_clean_does_not_block(self, tmp_path):
        import tests.test_guardian as guardian_tests
        dns = self._make_dns("203.0.113.10")
        g, fw, *_ , _ = guardian_tests.make_guardian(tmp_path, dns=dns)
        g._gstate = guardian.sm.GateState(state=guardian.sm.ALLOWED)
        fw.global_enabled = False
        _slow_tick(g)
        # echo + DNS 都 CLEAN → 继续 HOLD（确认窗），不回阻断
        assert g._gstate.state == guardian.sm.ALLOWED
        assert g._last_checks["DNS出口干净"] is True

    def test_dns_dirty_blocks_immediately(self, tmp_path):
        import tests.test_guardian as guardian_tests
        dns = self._make_dns("198.51.100.20")
        g, fw, *_ , _ = guardian_tests.make_guardian(tmp_path, dns=dns)
        g._gstate = guardian.sm.GateState(state=guardian.sm.ALLOWED)
        fw.global_enabled = False
        _slow_tick(g)
        assert g._gstate.state == guardian.sm.BLOCKED
        assert fw.global_enabled is True
        assert g._last_checks["DNS出口干净"] is False
        assert g._last_dns_ip == "198.51.100.20"

    def test_dns_unreachable_counts_as_unreachable(self, tmp_path):
        import tests.test_guardian as guardian_tests
        dns = self._make_dns(ok=False)
        g, fw, *_ , _ = guardian_tests.make_guardian(tmp_path, dns=dns)
        g._gstate = guardian.sm.GateState(state=guardian.sm.ALLOWED)
        fw.global_enabled = False
        # echo CLEAN、DNS UNREACHABLE → 综合为 UNREACHABLE，走计数升级
        for _ in range(guardian_tests.make_config().fail_unreachable_threshold):
            _slow_tick(g)
        assert g._gstate.state == guardian.sm.BLOCKED
        assert "enable" in fw.calls

    def test_dns_whitelist_override(self, tmp_path):
        """dns_whitelist 配置优先于 whitelist。"""
        import tests.test_guardian as guardian_tests
        cfg = guardian_tests.make_config(
            dns_whitelist=["198.51.100.20"])
        dns = self._make_dns("198.51.100.20")
        g, *_ , _ = guardian_tests.make_guardian(tmp_path, dns=dns)
        g.config = cfg
        verdict, _ = g._probe_dns_egress()
        assert verdict == policy.CLEAN

    def test_toast_dns_leak_reason(self, tmp_path, monkeypatch):
        """仅 DNS 泄漏（echo 出口干净）触发的阻断 Toast 按检查⑤解释。"""
        import tests.test_guardian as guardian_tests
        from core import messages
        dns = self._make_dns("198.51.100.20")
        np = guardian_tests.FakeNetprobe(echo_ip="203.0.113.10")
        g, fw, *_ , _ = guardian_tests.make_guardian(tmp_path, np=np, dns=dns)
        _slow_tick(g)
        text = "\n".join(g._toast_text(guardian.sm.NOTIFY_BLOCK))
        assert "DNS 泄漏" in text
        assert "198.51.100.20" in text
        # echo 出口脏时按出口解释，不显示 DNS 泄漏文案
        dns2 = self._make_dns("198.51.100.20")
        np2 = guardian_tests.FakeNetprobe(echo_ip="203.0.113.9")
        g2, *_ , _ = guardian_tests.make_guardian(tmp_path, np=np2, dns=dns2)
        _slow_tick(g2)
        text2 = "\n".join(g2._toast_text(guardian.sm.NOTIFY_BLOCK))
        assert "出口 IP 不干净" in text2
        assert "DNS 泄漏" not in text2

    def test_tray_details_show_dns_leak(self):
        from tray import State, StateEvent
        evt = StateEvent(
            state=State.BLOCKED,
            exit_ip="203.0.113.10",
            whitelist_hit=True,
            dns_leak_ip="198.51.100.20",
            checks={"mihomo进程": True, "TUN网卡": True, "fake-ip": True,
                    "echo出口": True, "DNS出口干净": False},
        )
        lines = evt.detail_lines()
        assert any("198.51.100.20" in ln for ln in lines)
        s = evt._status()
        assert "DNS 泄漏" in messages_reason(s)

    def test_probe_exception_is_unreachable(self, tmp_path):
        """探针抛异常不杀主循环，按 UNREACHABLE 处理。"""
        import tests.test_guardian as guardian_tests
        d = guardian_tests.FakeDns()
        def boom(domain, wl):
            raise RuntimeError("boom")
        d.check_dns_egress = boom
        g, *_ , _ = guardian_tests.make_guardian(tmp_path, dns=d)
        verdict, probe = g._probe_dns_egress()
        assert verdict == policy.UNREACHABLE
        assert probe.ok is False


def messages_reason(s):
    from core import messages
    return messages.reason_text(s)
