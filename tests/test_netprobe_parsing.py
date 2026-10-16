"""netprobe 解析函数离线单元测试：只测纯函数，不发网络请求。"""

import pytest

from winplat.netprobe import check_tun_adapter, parse_ip_sb, parse_trace_ip


class TestParseTraceIp:
    def test_standard_trace(self):
        text = (
            "fl=123f4\n"
            "h=www.cloudflare.com\n"
            "ip=203.0.113.7\n"
            "ts=1700000000.123\n"
            "visit_scheme=https\n"
            "uag=claude-guard/1.0\n"
            "colo=LAX\n"
            "http=http/2\n"
        )
        assert parse_trace_ip(text) == "203.0.113.7"

    def test_ipv6_trace(self):
        text = "ip=2606:4700:4700::1111\nloc=US\n"
        assert parse_trace_ip(text) == "2606:4700:4700::1111"

    def test_ip_line_with_spaces(self):
        assert parse_trace_ip("ip= 198.51.100.5 ") == "198.51.100.5"

    def test_missing_ip_line(self):
        assert parse_trace_ip("h=www.cloudflare.com\ncolo=LAX\n") is None

    def test_empty_value(self):
        assert parse_trace_ip("ip=\n") is None

    def test_empty_text(self):
        assert parse_trace_ip("") is None


class TestParseIpSb:
    def test_plain_ip(self):
        assert parse_ip_sb("203.0.113.9") == "203.0.113.9"

    def test_trailing_newline(self):
        assert parse_ip_sb("203.0.113.9\n") == "203.0.113.9"

    def test_surrounding_whitespace(self):
        assert parse_ip_sb("  198.51.100.1\r\n") == "198.51.100.1"

    def test_ipv6(self):
        assert parse_ip_sb("2606:4700::1\n") == "2606:4700::1"

    def test_empty(self):
        assert parse_ip_sb("") is None
        assert parse_ip_sb("\n") is None

    def test_multiline_rejected(self):
        assert parse_ip_sb("203.0.113.9\n198.51.100.1\n") is None


class TestCheckTunAdapterOffline:
    """网卡检测：不依赖真实机器，验证 fake-ip 段匹配逻辑。

    check_tun_adapter 直接调用 psutil，无法注入；这里通过子类/monkeypatch
    psutil.net_if_addrs 验证匹配逻辑。
    """

    @pytest.fixture
    def patch_addrs(self, monkeypatch):
        def _patch(mapping):
            monkeypatch.setattr("winplat.netprobe.psutil.net_if_addrs", lambda: mapping)

        return _patch

    def _ifaddr(self, address, family):
        # 只用到 .address；用简单 namespace 即可
        from types import SimpleNamespace

        return SimpleNamespace(address=address, family=family)

    def test_keyword_match(self, patch_addrs):
        import socket

        patch_addrs({
            "Mihomo": [self._ifaddr("10.0.0.5", socket.AF_INET)],
            "Ethernet": [self._ifaddr("192.168.1.2", socket.AF_INET)],
        })
        present, name = check_tun_adapter(["mihomo", "clash"])
        assert present is True
        assert name == "Mihomo"

    def test_fakeip_range_match(self, patch_addrs):
        import socket

        patch_addrs({
            "Meta": [self._ifaddr("198.18.0.7", socket.AF_INET)],
        })
        # 关键词列表不含 meta，仅靠 fake-ip 段命中
        present, name = check_tun_adapter(["utun"], "198.18.0.0/15")
        assert present is True
        assert name == "Meta"

    def test_no_match(self, patch_addrs):
        import socket

        patch_addrs({
            "Ethernet": [self._ifaddr("192.168.1.2", socket.AF_INET)],
            "Loopback": [self._ifaddr("127.0.0.1", socket.AF_INET)],
        })
        present, name = check_tun_adapter(["mihomo", "clash", "utun", "verge"])
        assert present is False
        assert name is None

    def test_bad_fakeip_range_falls_back_to_keywords(self, patch_addrs):
        import socket

        patch_addrs({
            "Clash": [self._ifaddr("10.0.0.5", socket.AF_INET)],
        })
        present, name = check_tun_adapter(["clash"], "not-a-network")
        assert present is True
        assert name == "Clash"

    def test_case_insensitive(self, patch_addrs):
        import socket

        patch_addrs({
            "Verge TUN": [self._ifaddr("192.168.1.2", socket.AF_INET)],
        })
        present, _ = check_tun_adapter(["verge"])
        assert present is True
