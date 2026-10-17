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

# --check 自检开头两条文案（分隔线之前；P3-18 收敛进 messages.py）。
# 返回 (主结论提示, 只读说明)：探测未全部成功时的主结论与只读声明。
# 分隔线之后的技术明细保持豁免。


def selfcheck_intro() -> tuple[str, str]:
    """--check 自检分隔线前的两条文案：(未确认提示, 只读说明)。"""
    return ("⏳ 当前检查未见异常，但探测未全部成功，"
            "未能确认是否可以放行（以托盘实际状态为准）",
            "（自检为只读探测，不改变防火墙当前状态）")

# 漂移提示（托盘详情气泡 / Toast 共用）。漂移检测比对的是封禁 IP 段
# （blocked_cidrs，Claude 在 Anthropic 侧的落地网段），不是出口白名单——
# 提示必须指向正确的配置项，否则用户改白名单永远解决不了告警。
DRIFT_HINT = "⚠ Claude 相关的 IP 段发生了变化，请检查配置里的拦截 IP 段是否需要更新"


@dataclass(frozen=True)
class Status:
    """用户视角的状态快照；字段值为 None 表示尚未探测。

    字段命名刻意避开技术术语，由调用方（guardian/tray）负责把
    具体检查结果映射到这些中性字段上。
    """

    blocking: bool = True            # 防火墙是否处于拦截
    paused: bool = False
    override_min_left: int | None = None  # 临时放行剩余分钟
    confirming: bool = False         # 启动确认期：检查通过、等待连续确认
    proxy_ok: bool | None = None     # Clash 代理在运行
    tunnel_ok: bool | None = None    # TUN 已接管流量
    dns_ok: bool | None = None       # DNS 没有泄漏（fake-ip 生效）
    # 检查⑤（DNS 出口探针）三态：True=干净 False=泄漏 None=未探测/不可达。
    # 与 dns_leak_ip 分工：本字段承载判定结果（含不可达），后者只在
    # 确认泄漏时携带递归出口 IP 供文案展示。
    dns_egress_ok: bool | None = None
    dns_leak_ip: str | None = None   # DNS 解析出口（检查⑤）；None=未探测/干净
    probe_ok: bool | None = None     # 出口探测可达
    exit_ip: str | None = None
    in_whitelist: bool | None = None
    # 确认窗进度 (已过轮数, 总轮数)，仅 confirming 时有值
    confirm_progress: tuple[int, int] | None = None


def status_line(s: Status) -> str:
    """第一行：防火墙状态（用户最关心的）。

    override_min_left 为负数表示“临时放行中但剩余时间未知”，只显示状态。
    """
    if s.paused:
        # 暂停语义 = 冻结在阻断态（fail-closed）：pause 命令会强制
        # 恢复拦截——文案必须如实（曾写"保持当前状态"与实际矛盾）。
        return "⏸ 守护已暂停（防火墙保持拦截）"
    if s.override_min_left is not None:
        if s.override_min_left < 0:
            return "⏳ 已临时放行 Claude"
        return f"⏳ 已临时放行 Claude（剩余 {s.override_min_left} 分钟）"
    if s.blocking:
        # 拦截原因有两种：环境有风险（出口脏/DNS 泄漏/Clash 异常）→ 风险真实
        # 存在，阻断只是挡住使用；未开 Clash → 风险尚未发生。文案不能断言
        # "无泄漏风险"（曾有 DNS 泄漏态显示该字样自相矛盾，用户实测发现）。
        if s.confirming:
            prog = (f" {s.confirm_progress[0]}/{s.confirm_progress[1]}"
                    if s.confirm_progress else "")
            return f"🛡 防火墙正在拦截（确认中{prog}，确认通过后自动放行）"
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
    # 检查⑤探测失败 ≠ 泄漏：显示"无法确认"而不是落到兜底"环境正常"
    # （拦截态+环境正常的矛盾文案的最后一个残留路径）。
    if s.dns_egress_ok is None:
        return "暂时无法确认 DNS 是否泄漏（探测失败，稍后重试）"
    if s.probe_ok is False:
        return "暂时无法确认出口 IP（探测失败，稍后重试）"
    if s.in_whitelist is False:
        return f"出口 IP 不干净（当前出口 {s.exit_ip or '未知'}，不在你的白名单里）"
    if s.dns_egress_ok is False:
        # 有应答但拿不到可解析出口 IP（各更强的失败分支都未命中）：
        # 按"无法确认"处理，绝不落兜底"环境正常"（P2-4，fail-closed）。
        return "DNS 解析出口异常（探针应答无法确认出口，已按泄漏处理）"
    if s.confirming:
        return "检查已通过，正在确认环境稳定（稍后自动放行）"
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
    # —— 三态渲染：✓=通过 ✗=未通过 –=未探测（None 显示 – 而非 ✗，
    # 未探测断言成失败会误导）。DNS 用检查⑤判定（dns_egress_ok），
    # 不再镜像 fake-ip 结果。塞不下就不加（完整版看右键"状态详情"）。
    pairs = [("代理", s.proxy_ok), ("TUN", s.tunnel_ok),
             ("解析", s.dns_ok), ("出口", s.probe_ok),
             ("DNS", s.dns_egress_ok)]
    parts = [f"{label}{'✓' if v is True else '✗' if v is False else '–'}"
             for label, v in pairs]
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
    return TOAST_TITLE, "🛡 临时放行已结束，防火墙恢复拦截 Claude"


def toast_paused() -> tuple[str, str]:
    """守护暂停的 Toast。"""
    return TOAST_TITLE, "⏸ 守护已暂停：防火墙保持拦截，不再自动检查环境"


def toast_resumed() -> tuple[str, str]:
    """守护恢复的 Toast。"""
    return TOAST_TITLE, "▶ 守护已恢复：重新开始检查环境"


def toast_drift() -> tuple[str, str]:
    """IP 段漂移告警的 Toast。"""
    return TOAST_TITLE, DRIFT_HINT
