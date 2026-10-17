"""Configuration loading and validation (pure logic, no side effects)."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_FIELDS_INT_POSITIVE = (
    "fast_tick_sec",
    "slow_tick_sec",
    "pass_confirm_count",
    "fail_unreachable_threshold",
    "doh_check_interval_min",
    "ripe_check_interval_hours",
    "override_minutes",
    "log_retention_days",
)
_FIELDS_STR_NONEMPTY = (
    "rule_name_v4",
    "rule_name_v6",
    "fakeip_range",
    "mihomo_process",
    "asn",
    "log_dir",
)
_FIELDS_STR_LIST = (
    "blocked_cidrs_v4",
    "blocked_cidrs_v6",
    "whitelist",
    "echo_endpoints",
    "tun_adapter_keywords",
    "claude_domains",
)


class ConfigError(ValueError):
    """Raised when config.json is missing, unreadable, or invalid."""


@dataclass(frozen=True)
class Config:
    blocked_cidrs_v4: list[str] = field(default_factory=list)
    blocked_cidrs_v6: list[str] = field(default_factory=list)
    rule_name_v4: str = ""
    rule_name_v6: str = ""
    rule_name_fakeip: str = "CG-FakeIP"
    whitelist: list[str] = field(default_factory=list)
    echo_endpoints: list[str] = field(default_factory=list)
    fakeip_range: str = ""
    mihomo_process: str = ""
    tun_adapter_keywords: list[str] = field(default_factory=list)
    fast_tick_sec: int = 0
    slow_tick_sec: int = 0
    pass_confirm_count: int = 0
    fail_unreachable_threshold: int = 0
    doh_check_interval_min: int = 0
    ripe_check_interval_hours: int = 0
    override_minutes: int = 0
    claude_domains: list[str] = field(default_factory=list)
    asn: str = ""
    log_dir: str = ""
    log_retention_days: int = 0
    dns_probe_domain: str = "whoami.ds.akahelp.net"
    dns_whitelist: list[str] = field(default_factory=list)
    # 检查⑤出口归属国白名单（ISO 3166-1 alpha-2，如 "US"）；空=仅段判定
    dns_egress_countries: list[str] = field(default_factory=list)


def _require_str_nonempty(data: dict[str, Any], key: str, errors: list[str]) -> None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"字段 '{key}' 必须是非空字符串（当前值: {value!r}）")


def _require_int_positive(data: dict[str, Any], key: str, errors: list[str]) -> None:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        errors.append(f"字段 '{key}' 必须是正整数（当前值: {value!r}）")


def _require_str_list(data: dict[str, Any], key: str, errors: list[str]) -> None:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        errors.append(f"字段 '{key}' 必须是字符串列表（当前值: {value!r}）")


def _validate_cidr_list(data: dict[str, Any], key: str, errors: list[str]) -> None:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        errors.append(f"字段 '{key}' 必须是字符串列表（当前值: {value!r}）")
        return
    for cidr in value:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"字段 '{key}' 含非法 CIDR: {cidr!r}")


def _validate_whitelist(data: dict[str, Any], errors: list[str]) -> None:
    value = data.get("whitelist")
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        errors.append(f"字段 'whitelist' 必须是字符串列表（当前值: {value!r}）")
        return
    if not value:
        errors.append("字段 'whitelist' 不能为空：白名单为空时工具永远无法放行")
        return
    for entry in value:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            errors.append(f"字段 'whitelist' 含非法 IP/CIDR: {entry!r}")


def validate_config(data: Any) -> None:
    """Validate a parsed config dict; raise ConfigError with readable messages."""
    if not isinstance(data, dict):
        raise ConfigError(f"配置根节点必须是 JSON 对象（当前类型: {type(data).__name__}）")

    errors: list[str] = []

    for key in _FIELDS_STR_NONEMPTY:
        _require_str_nonempty(data, key, errors)
    for key in _FIELDS_INT_POSITIVE:
        _require_int_positive(data, key, errors)
    for key in _FIELDS_STR_LIST:
        _require_str_list(data, key, errors)

    _validate_cidr_list(data, "blocked_cidrs_v4", errors)
    _validate_cidr_list(data, "blocked_cidrs_v6", errors)
    _validate_whitelist(data, errors)

    # 可选 dns_whitelist：缺省复用 whitelist；给了就必须是合法 IP/CIDR 列表
    dns_wl = data.get("dns_whitelist")
    if dns_wl is not None:
        if not isinstance(dns_wl, list) or not all(isinstance(x, str) for x in dns_wl):
            errors.append(f"字段 'dns_whitelist' 必须是字符串列表（当前值: {dns_wl!r}）")
        else:
            for entry in dns_wl:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    errors.append(f"字段 'dns_whitelist' 含非法 IP/CIDR: {entry!r}")
    # 可选 dns_egress_countries：ISO 3166-1 alpha-2 国家码列表（如 ["US"]）
    dec = data.get("dns_egress_countries")
    if dec is not None:
        if (not isinstance(dec, list)
                or not all(isinstance(x, str) and len(x) == 2 and x.isalpha()
                           for x in dec)):
            errors.append(f"字段 'dns_egress_countries' 必须是两位国家码列表（当前值: {dec!r}）")
    # 可选 rule_name_fakeip：给了就必须是非空字符串，缺省 "CG-FakeIP"
    rnf = data.get("rule_name_fakeip")
    if rnf is not None and (not isinstance(rnf, str) or not rnf.strip()):
        errors.append(f"字段 'rule_name_fakeip' 必须是非空字符串（当前值: {rnf!r}）")
    # 可选 dns_probe_domain：给了就必须是非空字符串
    dpd = data.get("dns_probe_domain")
    if dpd is not None and (not isinstance(dpd, str) or not dpd.strip()):
        errors.append(f"字段 'dns_probe_domain' 必须是非空字符串（当前值: {dpd!r}）")

    if not data.get("echo_endpoints"):
        errors.append("字段 'echo_endpoints' 不能为空：阻断态探测依赖 echo 端点（G-5）")
    if not data.get("claude_domains"):
        errors.append("字段 'claude_domains' 不能为空：漂移检测依赖域名列表（D-1）")
    if not data.get("blocked_cidrs_v4"):
        errors.append("字段 'blocked_cidrs_v4' 不能为空：门禁需要至少一个封禁段（B-1）")

    if errors:
        raise ConfigError("配置校验失败，共 %d 处问题：\n  - %s" % (len(errors), "\n  - ".join(errors)))


def load(path: str | Path) -> Config:
    """Load and validate config.json; return a Config dataclass."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"配置文件不存在: {p}") from exc
    except OSError as exc:
        raise ConfigError(f"配置文件无法读取: {p}（{exc}）") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON: {p}（第 {exc.lineno} 行: {exc.msg}）") from exc

    validate_config(data)
    cfg = Config(
        **{f: data[f] for f in (
            _FIELDS_INT_POSITIVE + _FIELDS_STR_NONEMPTY + _FIELDS_STR_LIST
        )}
    )
    # 可选字段：有默认值者缺省补齐
    object.__setattr__(cfg, "rule_name_fakeip",
                       data.get("rule_name_fakeip", "CG-FakeIP"))
    object.__setattr__(cfg, "dns_probe_domain",
                       data.get("dns_probe_domain", "whoami.ds.akahelp.net"))
    object.__setattr__(cfg, "dns_whitelist",
                       list(data.get("dns_whitelist") or data.get("whitelist") or []))
    object.__setattr__(cfg, "dns_egress_countries",
                       [c.upper() for c in (data.get("dns_egress_countries") or [])])
    return cfg
