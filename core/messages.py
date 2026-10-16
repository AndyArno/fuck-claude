# -*- coding: utf-8 -*-
"""用户可见文案集中模块（唯一文案来源）。

所有面向用户的信息（托盘 tooltip、状态详情气泡、Toast 通知、
--check / MessageBox 输出）都必须从这里取文案，禁止各处自行拼接
技术术语。技术细节（mihomo/TUN/fake-ip/DIRTY/CLEAN 等）只允许
出现在日志文件和“技术细节”分隔线之后。

信息模型：
- 第一行永远是防火墙状态（拦截 / 放行 / 临时放行 / 暂停）；
- 拦截态必须附大白话原因，按检查项优先级取第一个未通过的。
"""
from __future__ import annotations

from dataclasses import dataclass

TOAST_TITLE = "Claude Guard"

# 排障技术细节与主结论之间的分隔线
TECH_SEPARATOR = "——技术细节——"

# 漂移提示（托盘详情气泡 / Toast 共用）
DRIFT_HINT = "⚠ Claude 相关的 IP 段发生了变化，请检查白名单是否需要更新"


@dataclass(frozen=True)
class Status:
    """用户视角的状态快照；字段值为 None 表示尚未探测。

    字段命名刻意避开技术术语，由调用方（guardian/tray）负责把
    具体检查结果映射到这些中性字段上。
    """

    blocking: bool = True            # 防火墙是否处于拦截
    paused: bool = False
    override_min_left: int | None = None  # 临时放行剩余分钟
    proxy_ok: bool | None = None     # Clash 代理在运行
    tunnel_ok: bool | None = None    # TUN 已接管流量
    dns_ok: bool | None = None       # DNS 没有泄漏（fake-ip 生效）
    dns_leak_ip: str | None = None   # DNS 解析出口（检查⑤）；None=未探测/未泄漏
    probe_ok: bool | None = None     # 出口探测可达
    exit_ip: str | None = None
    in_whitelist: bool | None = None


def status_line(s: Status) -> str:
    """第一行：防火墙状态（用户最关心的）。

    override_min_left 为负数表示“临时放行中但剩余时间未知”，只显示状态。
    """
    if s.paused:
        return "⏸ 守护已暂停（防火墙保持当前状态）"
    if s.override_min_left is not None:
        if s.override_min_left < 0:
            return "⏳ 已临时放行 Claude"
        return f"⏳ 已临时放行 Claude（剩余 {s.override_min_left} 分钟）"
    if s.blocking:
        # 拦截原因有两种：环境有风险（出口脏/DNS 泄漏/Clash 异常）→ 风险真实
        # 存在，阻断只是挡住使用；未开 Clash → 风险尚未发生。文案不能断言
        # "无泄漏风险"（曾有 DNS 泄漏态显示该字样自相矛盾，用户实测发现）。
        return "🛡 防火墙正在拦截 Claude（已阻断风险连接）"
    return "✅ 防火墙已放行 Claude（出口 IP 干净）"


def reason_text(s: Status) -> str:
    """大白话原因（不带“原因：”前缀），按检查项优先级取第一个未通过的。"""
    if s.proxy_ok is False:
        return "Clash 代理没有在运行"
    if s.tunnel_ok is False:
        return "Clash 没有接管网络流量（TUN 模式未生效）"
    if s.dns_ok is False:
        return "存在 DNS 泄漏（Claude 域名解析绕过了代理）"
    if s.dns_leak_ip is not None:
        return f"DNS 泄漏（解析出口 {s.dns_leak_ip}，不在白名单）"
    if s.probe_ok is False:
        return "暂时无法确认出口 IP（探测失败，稍后重试）"
    if s.in_whitelist is False:
        return f"出口 IP 不干净（当前出口 {s.exit_ip or '未知'}，不在你的白名单里）"
    return "代理环境正常，出口 IP 在白名单内"


def reason_line(s: Status) -> str:
    return f"原因：{reason_text(s)}"


def tooltip(s: Status) -> str:
    """托盘 tooltip。Windows 托盘 title 硬截断约 127 字符，超长会被砍——
    优先保证前两行（状态+原因/出口），第三行尽量塞精简检查摘要，
    塞不下时靠右键"状态详情"看完整版。"""
    line1 = status_line(s)
    if not s.paused and (s.blocking or s.override_min_left is not None):
        head = f"{line1}\n{reason_line(s)}"
    else:
        head = f"{line1}\n出口 IP：{s.exit_ip or '未知'}"
    # 精简检查行（用 Status 中性字段）："代理✓ TUN✓ 解析✓ 出口✓ DNS✗"
    # —— 只在 127 字符截断预算内附加，塞不下就不加（完整版看右键"状态详情"）
    pairs = [("代理", s.proxy_ok), ("TUN", s.tunnel_ok),
             ("解析", s.dns_ok), ("出口", s.probe_ok),
             ("DNS", s.dns_ok if s.dns_leak_ip is None else None)]
    parts = [f"{label}{'✓' if v else '✗'}" for label, v in pairs]
    summary = " ".join(parts)
    if len(head) + len(summary) + 1 <= 120:
        return f"{head}\n{summary}"
    return head


# ---- Toast 通知 -------------------------------------------------------
# 说明：core/statemachine.py 的 NOTIFY_* action 现在只携带中性标记
# （如 "fast_fail"/"check_fail"），真正的用户文案由 Guardian._toast_text
# 统一调本模块生成；state-machine 里的 message 字段不再是用户可见文案。

def toast_block(s: Status) -> tuple[str, str]:
    """状态切换为阻断时的 Toast。"""
    return TOAST_TITLE, f"🛡 Claude 已阻断：{reason_text(s)}"


def toast_allow() -> tuple[str, str]:
    """状态切换为放行时的 Toast。"""
    return TOAST_TITLE, "✅ Claude 已放行：出口 IP 干净"


def toast_override_start(minutes: int) -> tuple[str, str]:
    """临时放行开始的 Toast。"""
    return TOAST_TITLE, f"⏳ Claude 已临时放行 {minutes} 分钟（到期自动恢复拦截）"


def toast_override_end() -> tuple[str, str]:
    """临时放行到期、恢复阻断的 Toast。"""
    return TOAST_TITLE, "🛡 临时放行已结束，防火墙恢复拦截 Claude"


def toast_drift() -> tuple[str, str]:
    """IP 段漂移告警的 Toast。"""
    return TOAST_TITLE, DRIFT_HINT
