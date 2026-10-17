# -*- coding: utf-8 -*-
"""core/messages.py tooltip 回归测试（P1-1）。

背景：b47c09b 三态渲染改造删掉了 `summary = " ".join(parts)` 但保留引用，
tooltip() 每次调用必抛 NameError，被 tray._event_loop 的裸 except 吞掉，
托盘标题/菜单整体冻结——209 条测试无一覆盖才存活至今。
"""
from __future__ import annotations

import pytest

from core.messages import Status, reason_text, status_line, toast_block, tooltip


def _status(**kw) -> Status:
    base = dict(
        blocking=True, paused=False, override_min_left=None, confirming=False,
        proxy_ok=True, tunnel_ok=True, dns_ok=True, probe_ok=True,
        dns_egress_ok=True, dns_leak_ip=None, exit_ip="203.0.113.10",
        in_whitelist=True,
    )
    base.update(kw)
    return Status(**base)


class TestTooltip:
    def test_renders_all_states(self):
        """五种代表性状态：阻断+原因行 / 放行+出口行 / 暂停 / 临时放行 / 全未探测。"""
        cases = [
            _status(),                                        # 阻断+原因行
            _status(blocking=False),                          # 放行+出口行
            _status(paused=True),                             # 暂停
            _status(override_min_left=5),                     # 临时放行中
            _status(proxy_ok=None, tunnel_ok=None, dns_ok=None,
                    probe_ok=None, dns_egress_ok=None,
                    exit_ip=None, in_whitelist=None),         # 全未探测
        ]
        for s in cases:
            text = tooltip(s)
            assert isinstance(text, str)          # 不抛 NameError
            assert text.count("\n") >= 1          # 至少两行

    def test_three_state_glyphs_render(self):
        """三态渲染各出现一次：✓ 通过 / ✗ 未通过 / – 未探测。"""
        s = _status(proxy_ok=True, tunnel_ok=False, dns_ok=None)
        text = tooltip(s)
        assert "代理✓" in text
        assert "TUN✗" in text
        assert "解析–" in text

    def test_truncation_when_too_long(self):
        """超长 reason 触发降级：只返回 head（无第三行摘要）。"""
        # blocking+原因行路径：head 含 reason_line，构造超长出口 IP 撑长。
        s = _status(exit_ip="203.0.113." + "1" * 200, dns_egress_ok=False,
                    dns_leak_ip="198.51.100." + "2" * 200)
        text = tooltip(s)
        assert text.count("\n") == 1   # 只有 head 两行，摘要被裁
        # 摘要五个词组一个都没进来
        for label in ("代理", "TUN", "解析", "出口", "DNS"):
            assert f"{label}✓" not in text

    def test_summary_included_when_fits(self):
        """长度足够时第三行摘要完整存在（P1-1 修复的直接断言）。"""
        text = tooltip(_status())
        lines = text.split("\n")
        assert len(lines) == 3
        assert "代理✓" in lines[2] and "DNS✓" in lines[2]


class TestReasonDnsEgressFalse:
    """P2-4：dns_egress_ok=False 且 dns_leak_ip=None（akahelp 有应答
    无可解析 IP）不得落兜底"环境正常"。"""

    def test_reason_no_normal_environment(self):
        s = _status(dns_egress_ok=False, dns_leak_ip=None)
        text = reason_text(s)
        assert "环境正常" not in text
        assert "DNS" in text

    def test_toast_block_no_normal_environment(self):
        s = _status(dns_egress_ok=False, dns_leak_ip=None)
        title, body = toast_block(s)
        assert "环境正常" not in body
        assert "DNS" in body


def test_status_line_confirming_with_progress():
    s = Status(blocking=True, confirming=True, confirm_progress=(2, 3))
    assert "确认中 2/3" in status_line(s)


def test_status_line_confirming_without_progress_unchanged():
    s = Status(blocking=True, confirming=True)
    assert status_line(s) == "🛡 防火墙正在拦截（确认中，确认通过后自动放行）"
