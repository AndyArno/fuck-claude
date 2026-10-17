# -*- coding: utf-8 -*-
"""DNS 出口探针（检查⑤）测试：TXT 解析纯函数 + guardian 三态接入。"""
import logging
import ctypes
import struct

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
        d.check_dns_egress = lambda domain, wl, countries=None: (
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
        assert "set_blocking_on" in fw.calls

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
        def boom(domain, wl, countries=None):
            raise RuntimeError("boom")
        d.check_dns_egress = boom
        g, *_ , _ = guardian_tests.make_guardian(tmp_path, dns=d)
        verdict, probe = g._probe_dns_egress()
        assert verdict == policy.UNREACHABLE
        assert probe.ok is False


class TestCountryVerdict:
    """⑤归属国判定：段白名单优先 → 国家 → geo 失败三态。"""

    def _probe(self, records):
        return dnscheck.DnsEgressResult(ok=True, egress_ip=None, records=records)

    def test_country_in_allowed_is_clean(self, monkeypatch):
        # ECS=美国段（RFC 5737 文档段仅作假 IP，国家由桩决定）
        monkeypatch.setattr(dnscheck, "query_txt_windows",
                            lambda host: self._probe(
                                ("ns", "198.51.100.1", "ecs", "203.0.113.0/24/24")))
        monkeypatch.setattr(dnscheck, "lookup_country", lambda ip: "US")
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", [], allowed_countries=["US"])
        assert verdict == policy.CLEAN

    def test_country_not_allowed_is_dirty(self, monkeypatch):
        monkeypatch.setattr(dnscheck, "query_txt_windows",
                            lambda host: self._probe(
                                ("ns", "198.51.100.1", "ecs", "203.0.113.0/24/24")))
        # 真实家宽段场景：出口在中国 → 不在允许列表
        monkeypatch.setattr(dnscheck, "lookup_country", lambda ip: "CN")
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", [], allowed_countries=["US"])
        assert verdict == policy.DIRTY

    def test_geo_failure_is_unreachable(self, monkeypatch):
        monkeypatch.setattr(dnscheck, "query_txt_windows",
                            lambda host: self._probe(
                                ("ns", "198.51.100.1", "ecs", "203.0.113.0/24/24")))
        monkeypatch.setattr(dnscheck, "lookup_country", lambda ip: None)
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", [], allowed_countries=["US"])
        assert verdict == policy.UNREACHABLE

    def test_cidr_whitelist_beats_country(self, monkeypatch):
        """段白名单命中时 CLEAN，即使国家不在允许列表（段=更强证据）。"""
        monkeypatch.setattr(dnscheck, "query_txt_windows",
                            lambda host: self._probe(
                                ("ns", "198.51.100.1", "ecs", "203.0.113.0/24/24")))
        monkeypatch.setattr(dnscheck, "lookup_country", lambda ip: "CN")
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/24"],
            allowed_countries=["US"])
        assert verdict == policy.CLEAN

    def test_no_countries_falls_back_to_cidr_only(self, monkeypatch):
        """allowed_countries 为空：跳过国家判定，仅段白名单。"""
        monkeypatch.setattr(dnscheck, "query_txt_windows",
                            lambda host: self._probe(
                                ("ns", "198.51.100.1", "ecs", "203.0.113.0/24/24")))
        calls = []
        monkeypatch.setattr(dnscheck, "lookup_country",
                            lambda ip: calls.append(ip) or "US")
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/24"])
        assert verdict == policy.CLEAN
        assert calls == []  # 未配置国家 → 不查 geo

    def test_lookup_country_caches_by_prefix(self, monkeypatch):
        """/24 缓存：同段两次查询只打一次外部服务。"""
        calls = []
        def fake_get(url, timeout=None):
            calls.append(url)

            class R:
                def raise_for_status(self): pass
                def json(self): return {"country": "US"}
            return R()
        monkeypatch.setattr(dnscheck.requests, "get", fake_get)
        dnscheck._geo_cache.clear()
        assert dnscheck.lookup_country("203.0.113.5") == "US"
        assert dnscheck.lookup_country("203.0.113.99") == "US"  # 同 /24
        assert len(calls) == 1
        assert dnscheck.lookup_country("198.51.100.7") == "US"  # 异段
        assert len(calls) == 2

    def test_geo_failure_short_ttl_then_retry(self, monkeypatch):
        """P2-2：失败负缓存 60s——失败后 60s 内重查会真正再发请求。"""
        calls = []
        state = {"fail": True}

        def fake_get(url, timeout=None):
            calls.append(url)

            class R:
                def raise_for_status(self):
                    if state["fail"]:
                        raise RuntimeError("boom")

                def json(self):
                    return {"country": "US"}
            return R()
        monkeypatch.setattr(dnscheck.requests, "get", fake_get)
        dnscheck._geo_cache.clear()
        assert dnscheck.lookup_country("203.0.113.5") is None
        # 仍在短 TTL 内：缓存命中（不再发请求），但返回 None
        assert dnscheck.lookup_country("203.0.113.5") is None
        assert len(calls) == 1
        # 越过 60s TTL：缓存过期 → 真正重查，服务恢复 → 成功按 1h 缓存
        key = next(iter(dnscheck._geo_cache))
        ts, val = dnscheck._geo_cache[key]
        dnscheck._geo_cache[key] = (ts - 61.0, val)
        state["fail"] = False
        assert dnscheck.lookup_country("203.0.113.5") == "US"
        assert len(calls) == 2
        # 成功后再次查询走 1h 缓存
        assert dnscheck.lookup_country("203.0.113.5") == "US"
        assert len(calls) == 2

    def test_geo_cache_sweeps_expired_entries(self, monkeypatch):
        """P2-2 顺手清理：写入时剔除过期项，缓存不无限增长。"""
        monkeypatch.setattr(dnscheck.requests, "get",
                            lambda url, timeout=None: (_ for _ in ()).throw(
                                RuntimeError("net down")))
        dnscheck._geo_cache.clear()
        assert dnscheck.lookup_country("203.0.113.5") is None
        assert dnscheck.lookup_country("198.51.100.5") is None
        assert len(dnscheck._geo_cache) == 2
        # 把其中一项时间戳回拨到过期线之外
        key = "203.0.113.0"
        assert key in dnscheck._geo_cache
        ts, val = dnscheck._geo_cache[key]
        dnscheck._geo_cache[key] = (ts - 61.0, val)
        assert dnscheck.lookup_country("203.0.113.6") is None
        # 过期项被清理后随本次失败重写，时间戳刷新
        assert dnscheck._geo_cache[key][0] > ts
        assert len(dnscheck._geo_cache) == 2


# ------------------------------------------------------- parse_ecs_cidr

class TestParseEcsCidr:
    def test_triple_form(self):
        assert dnscheck.parse_ecs_cidr(
            ("ns", "203.0.113.0/24/24")) == "203.0.113.0/24"

    def test_plain_cidr(self):
        assert dnscheck.parse_ecs_cidr(("203.0.113.0/24",)) == "203.0.113.0/24"

    def test_comma_separated_tokens(self):
        assert dnscheck.parse_ecs_cidr(
            ("ns,203.0.113.0/24/24",)) == "203.0.113.0/24"

    def test_no_ecs(self):
        assert dnscheck.parse_ecs_cidr(("ns", "198.51.100.20")) is None

    def test_empty(self):
        assert dnscheck.parse_ecs_cidr(()) is None

    def test_invalid_cidr_skipped(self):
        assert dnscheck.parse_ecs_cidr(("999.0.113.0/24",)) is None


# ---------------------------------------------- check⑤ ECS 三判定（离线）

def _probe(records, egress_ip=None):
    return dnscheck.DnsEgressResult(ok=True, egress_ip=egress_ip,
                                    records=records)


class TestCheckDnsEgressEcs:
    def test_ecs_in_whitelist_clean(self, monkeypatch):
        """判定1：ECS 网段精确命中段白名单 → CLEAN。"""
        _patch_query(monkeypatch, _probe(("ns", "203.0.113.0/24/24")))
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/24"])
        assert verdict == policy.CLEAN

    def test_ecs_supernet_of_whitelist_entry_clean(self, monkeypatch):
        """判定1：ECS /24 是白名单 /16 的子网 → subnet_of 命中 → CLEAN。"""
        _patch_query(monkeypatch, _probe(("ecs", "203.0.113.0/24/24")))
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/16"])
        assert verdict == policy.CLEAN

    def test_ecs_country_attribution_uses_geo(self, monkeypatch):
        """判定2：ECS /16 不在段白名单 → 归属国判定走 geo（取网段首地址）。"""
        _patch_query(monkeypatch, _probe(("ecs", "198.51.100.0/16/16")))
        monkeypatch.setattr(dnscheck, "lookup_country",
                            lambda ip: "US")
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/24"],
            allowed_countries=["US"])
        assert verdict == policy.CLEAN

    def test_ecs_country_not_allowed_dirty(self, monkeypatch):
        _patch_query(monkeypatch, _probe(("ecs", "198.51.100.0/16/16")))
        monkeypatch.setattr(dnscheck, "lookup_country", lambda ip: "CN")
        verdict, _ = dnscheck.check_dns_egress(
            "whoami.ds.akahelp.net", ["203.0.113.0/24"],
            allowed_countries=["US"])
        assert verdict == policy.DIRTY


# ----------------------------------------------------- check_fakeip 边界

class TestCheckFakeipEdges:
    def test_bad_range_value_error(self):
        r = dnscheck.check_fakeip("claude.example", fakeip_range="not-a-cidr")
        assert r.ok is False and r.error is not None
        assert "bad fakeip_range" in r.error

    def test_resolver_oserror(self):
        def boom(host):
            raise OSError("net down")
        r = dnscheck.check_fakeip("claude.example", resolver=boom)
        assert r.ok is False and r.error is not None
        assert "resolve failed" in r.error

    def test_empty_resolution(self):
        r = dnscheck.check_fakeip("claude.example", resolver=lambda h: ())
        assert r.ok is False and r.error == "no addresses resolved"

    def test_first_address_in_range(self):
        r = dnscheck.check_fakeip(
            "claude.example",
            fakeip_range="198.18.0.0/15",
            resolver=lambda h: ("198.18.0.1",))
        assert r.ok is True and r.in_fakeip_range is True

    def test_last_address_in_range(self):
        # /15 198.18.0.0/15 的末地址是 198.19.255.255
        r = dnscheck.check_fakeip(
            "claude.example",
            fakeip_range="198.18.0.0/15",
            resolver=lambda h: ("198.19.255.255",))
        assert r.ok is True and r.in_fakeip_range is True

    def test_adjacent_prefix_not_in_range(self):
        # 198.18.0.0/15 只覆盖 198.18.x–198.19.x；198.20.0.1 是相邻段
        r = dnscheck.check_fakeip(
            "claude.example",
            fakeip_range="198.18.0.0/15",
            resolver=lambda h: ("198.20.0.1",))
        assert r.ok is True and r.in_fakeip_range is False

    def test_unparseable_ip_ignored(self):
        r = dnscheck.check_fakeip(
            "claude.example",
            fakeip_range="198.18.0.0/15",
            resolver=lambda h: ("not-an-ip",))
        assert r.ok is True and r.in_fakeip_range is False


def messages_reason(s):
    from core import messages
    return messages.reason_text(s)


# ---- P3-3：TXT 字符串数越界防护（_read_string_array 不抛 struct.error）-------

def _make_txt_record_bytes(count: int) -> bytes:
    """离线构造 DNS_TXT_DATAA 原始字节：StringCount + 内联指针数组。"""
    return struct.pack("<I4x", count) + b"\x00" * 56


class TestTxtCountGuard:
    def test_count_8_no_struct_error(self):
        """P3-3：count=8 超出 64 字节 Data 可容纳的 7 个指针，应截断不越界。"""
        data = _make_txt_record_bytes(8)
        texts = dnscheck._read_string_array(data, 7)
        assert texts == []

    def test_count_63_clamped_no_struct_error(self):
        data = _make_txt_record_bytes(63)
        # 计算与生产同口径的上限：偏移 8 起，每指针 8 字节
        max_count = (64 - dnscheck._STRINGARRAY_OFFSET) // 8
        assert max_count == 7
        texts = dnscheck._read_string_array(data, max_count)
        assert texts == []

    def test_query_txt_windows_clamps_count(self, monkeypatch):
        """count=8 时 query_txt_windows 走截断分支，返回 no TXT records 而非抛异常。"""
        rec = dnscheck._DnsRecordHead()
        rec.wType = dnscheck.DNS_TYPE_TXT
        rec.Data = (ctypes.c_ubyte * 64)(
            *[8] + [0] * 63)  # StringCount=8，其余为 0（指针全 NULL）

        class FakeHead:
            def __init__(self):
                self.wType = dnscheck.DNS_TYPE_TXT
                self.Data = rec.Data
                self.pNext = None

        class FakeDnsapi:
            def DnsQuery_A(self, *args):
                return 0
            def DnsRecordListFree(self, *args):
                pass

        fake_record = FakeHead()
        fake_record.wType = dnscheck.DNS_TYPE_TXT
        monkeypatch.setattr(dnscheck.ctypes, "WinDLL", lambda *a, **k: FakeDnsapi())
        # 用真实 _DnsRecordHead 实例走 cast 路径
        holder = dnscheck._DnsRecordHead()
        holder.wType = dnscheck.DNS_TYPE_TXT
        holder.Data = (ctypes.c_ubyte * 64)(8, *[0] * 63)
        ptr = ctypes.cast(ctypes.pointer(holder), ctypes.c_void_p)
        monkeypatch.setattr(ctypes, "cast",
                            lambda p, t: type("C", (), {"contents": holder})())
        result = dnscheck.query_txt_windows("whoami.ds.akahelp.net")
        assert result.ok is False
        assert "no TXT records parsed" in (result.error or "")


def test_check_fakeip_default_resolver_queries_ipv4_only(monkeypatch):
    """默认解析器只发 A 查询：AAAA 在 fake-ip 判定中无意义（段是 IPv4），
    且显式 AAAA 查询绕过 mihomo 本地应答走上游递归，实测单发 stall 8-11s
    （慢轮间隔 17.5s 的隐藏成本，曾每轮都付）。"""
    import socket as s
    from winplat import dnscheck

    families = []

    def fake_getaddrinfo(host, port, family, *a, **k):
        families.append(family)
        return [(2, 1, 6, "", ("198.18.0.7", 0))]

    monkeypatch.setattr(dnscheck.socket, "getaddrinfo", fake_getaddrinfo)
    r = dnscheck.check_fakeip("claude.ai", "198.18.0.0/15")
    assert r.ok and r.in_fakeip_range
    assert families and set(families) == {s.AF_INET}
