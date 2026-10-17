# -*- coding: utf-8 -*-
"""ripecheck 测试（P3-10）：畸形 payload 与 fetch 异常零覆盖补齐。

样本 CIDR 一律用文档段（RFC 5737 / RFC 1918），禁止真实网段。
"""
import pytest

from winplat import ripecheck


class TestParsePrefixes:
    def test_normal_payload(self):
        payload = {"data": {"prefixes": [
            {"prefix": "203.0.113.0/24"},
            {"prefix": "198.51.100.0/24"},
        ]}}
        assert ripecheck.parse_prefixes(payload) == frozenset(
            {"203.0.113.0/24", "198.51.100.0/24"})

    def test_missing_data_key(self):
        """缺 data 键 → 空集合，不炸。"""
        assert ripecheck.parse_prefixes({}) == frozenset()

    def test_missing_prefixes_key(self):
        assert ripecheck.parse_prefixes({"data": {}}) == frozenset()

    def test_non_dict_items_skipped(self):
        """prefixes 含非 dict 元素 → 跳过，不抛 AttributeError。"""
        payload = {"data": {"prefixes": ["198.51.100.0/24", None, 42,
                                         {"prefix": "203.0.113.0/24"}]}}
        assert ripecheck.parse_prefixes(payload) == frozenset({"203.0.113.0/24"})

    def test_items_without_prefix(self):
        payload = {"data": {"prefixes": [{"foo": 1}, {}]}}
        assert ripecheck.parse_prefixes(payload) == frozenset()

    def test_empty_prefixes_list(self):
        assert ripecheck.parse_prefixes({"data": {"prefixes": []}}) == frozenset()

    def test_prefix_not_string_skipped(self):
        payload = {"data": {"prefixes": [{"prefix": 123}]}}
        assert ripecheck.parse_prefixes(payload) == frozenset()


class TestFetchAnnouncedPrefixes:
    def _patch_get(self, monkeypatch, get):
        monkeypatch.setattr(ripecheck.requests, "get", get)

    def test_request_exception_returns_not_ok(self, monkeypatch):
        """RequestException → ok=False + error，不炸。"""
        import requests

        def get(*a, **k):
            raise requests.ConnectionError("boom")
        self._patch_get(monkeypatch, get)
        r = ripecheck.fetch_announced_prefixes()
        assert r.ok is False and r.prefixes == frozenset()
        assert "boom" in r.error

    def test_timeout_returns_not_ok(self, monkeypatch):
        import requests

        def get(*a, **k):
            raise requests.Timeout("timed out")
        self._patch_get(monkeypatch, get)
        r = ripecheck.fetch_announced_prefixes()
        assert r.ok is False
        assert "timed out" in r.error

    def test_invalid_json_returns_not_ok(self, monkeypatch):
        class Resp:
            def raise_for_status(self):
                pass
            def json(self):
                raise ValueError("not json")
        self._patch_get(monkeypatch, lambda *a, **k: Resp())
        r = ripecheck.fetch_announced_prefixes()
        assert r.ok is False and r.prefixes == frozenset()

    def test_non_dict_payload_returns_not_ok(self, monkeypatch):
        """payload 不是 dict → parse_prefixes 抛 AttributeError，被兜住。"""
        class Resp:
            def raise_for_status(self):
                pass
            def json(self):
                return ["not", "a", "dict"]
        self._patch_get(monkeypatch, lambda *a, **k: Resp())
        r = ripecheck.fetch_announced_prefixes()
        assert r.ok is False and r.prefixes == frozenset()
        assert "unexpected payload" in r.error

    def test_empty_prefixes_returns_not_ok(self, monkeypatch):
        """空 prefixes → ok=False（fail-closed：无漂移证据≠漂移消失）。"""
        class Resp:
            def raise_for_status(self):
                pass
            def json(self):
                return {"data": {"prefixes": []}}
        self._patch_get(monkeypatch, lambda *a, **k: Resp())
        r = ripecheck.fetch_announced_prefixes()
        assert r.ok is False
        assert "no announced prefixes" in r.error

    def test_success_returns_prefixes(self, monkeypatch):
        class Resp:
            def raise_for_status(self):
                pass
            def json(self):
                return {"data": {"prefixes": [{"prefix": "198.51.100.0/24"}]}}
        self._patch_get(monkeypatch, lambda *a, **k: Resp())
        r = ripecheck.fetch_announced_prefixes()
        assert r.ok is True
        assert r.prefixes == frozenset({"198.51.100.0/24"})
