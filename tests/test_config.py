"""Config load/validate tests — readable error messages for every bad path."""
import json

import pytest

from core import config as cfg


VALID = {
    "blocked_cidrs_v4": ["160.79.104.0/23"],
    "blocked_cidrs_v6": ["2607:6bc0::/48"],
    "rule_name_v4": "CG-Global",
    "rule_name_v6": "CG-V6",
    "whitelist": ["203.0.113.10"],
    "echo_endpoints": ["https://www.cloudflare.com/cdn-cgi/trace"],
    "fakeip_range": "198.18.0.0/15",
    "mihomo_process": "verge-mihomo.exe",
    "tun_adapter_keywords": ["mihomo"],
    "fast_tick_sec": 1,
    "slow_tick_sec": 5,
    "pass_confirm_count": 3,
    "fail_unreachable_threshold": 5,
    "doh_check_interval_min": 60,
    "ripe_check_interval_hours": 24,
    "override_minutes": 30,
    "claude_domains": ["claude.ai"],
    "asn": "AS399358",
    "log_dir": "logs",
    "log_retention_days": 30,
}


def write_cfg(tmp_path, data, name="config.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_load_valid_config(tmp_path):
    c = cfg.load(write_cfg(tmp_path, VALID))
    assert c.blocked_cidrs_v4 == ["160.79.104.0/23"]
    assert c.pass_confirm_count == 3
    assert c.whitelist == ["203.0.113.10"]


def test_missing_file_readable_error(tmp_path):
    with pytest.raises(cfg.ConfigError, match="不存在"):
        cfg.load(tmp_path / "nope.json")


def test_invalid_json_readable_error(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{broken", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="JSON"):
        cfg.load(p)


def test_root_not_object(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="JSON 对象"):
        cfg.load(p)


def test_missing_field(tmp_path):
    data = dict(VALID)
    del data["pass_confirm_count"]
    with pytest.raises(cfg.ConfigError, match="pass_confirm_count"):
        cfg.load(write_cfg(tmp_path, data))


def test_wrong_type_int_field(tmp_path):
    data = dict(VALID, fast_tick_sec="1")
    with pytest.raises(cfg.ConfigError, match="fast_tick_sec"):
        cfg.load(write_cfg(tmp_path, data))


def test_zero_int_rejected(tmp_path):
    data = dict(VALID, pass_confirm_count=0)
    with pytest.raises(cfg.ConfigError, match="正整数"):
        cfg.load(write_cfg(tmp_path, data))


def test_bad_cidr_format(tmp_path):
    data = dict(VALID, blocked_cidrs_v4=["160.79.104.0/99"])
    with pytest.raises(cfg.ConfigError, match="非法 CIDR"):
        cfg.load(write_cfg(tmp_path, data))


def test_bad_cidr_text(tmp_path):
    data = dict(VALID, blocked_cidrs_v6=["not-a-cidr"])
    with pytest.raises(cfg.ConfigError, match="非法 CIDR"):
        cfg.load(write_cfg(tmp_path, data))


def test_empty_whitelist_rejected(tmp_path):
    data = dict(VALID, whitelist=[])
    with pytest.raises(cfg.ConfigError, match="whitelist.*不能为空"):
        cfg.load(write_cfg(tmp_path, data))


def test_whitelist_bad_ip(tmp_path):
    data = dict(VALID, whitelist=["999.999.1.1"])
    with pytest.raises(cfg.ConfigError, match="非法 IP"):
        cfg.load(write_cfg(tmp_path, data))


def test_empty_echo_endpoints_rejected(tmp_path):
    data = dict(VALID, echo_endpoints=[])
    with pytest.raises(cfg.ConfigError, match="echo_endpoints"):
        cfg.load(write_cfg(tmp_path, data))


def test_multiple_errors_reported_together(tmp_path):
    data = dict(VALID)
    del data["rule_name_v4"]
    data["whitelist"] = []
    data["blocked_cidrs_v4"] = ["bad"]
    with pytest.raises(cfg.ConfigError) as exc:
        cfg.load(write_cfg(tmp_path, data))
    msg = str(exc.value)
    assert "rule_name_v4" in msg and "whitelist" in msg and "blocked_cidrs_v4" in msg
    assert "共 3 处" in msg


def test_dns_probe_domain_default(tmp_path):
    c = cfg.load(write_cfg(tmp_path, VALID))
    assert c.dns_probe_domain == "whoami.ds.akahelp.net"
    # 未配置 dns_whitelist → 复用 whitelist
    assert c.dns_whitelist == VALID["whitelist"]


def test_dns_probe_domain_custom(tmp_path):
    data = dict(VALID, dns_probe_domain="whoami.google.com")
    c = cfg.load(write_cfg(tmp_path, data))
    assert c.dns_probe_domain == "whoami.google.com"


def test_dns_probe_domain_invalid(tmp_path):
    data = dict(VALID, dns_probe_domain="")
    with pytest.raises(cfg.ConfigError, match="dns_probe_domain"):
        cfg.load(write_cfg(tmp_path, data))
    data = dict(VALID, dns_probe_domain=42)
    with pytest.raises(cfg.ConfigError, match="dns_probe_domain"):
        cfg.load(write_cfg(tmp_path, data))


def test_dns_whitelist_override(tmp_path):
    data = dict(VALID, dns_whitelist=["198.51.100.20"])
    c = cfg.load(write_cfg(tmp_path, data))
    assert c.dns_whitelist == ["198.51.100.20"]
    assert c.whitelist == VALID["whitelist"]


def test_dns_whitelist_bad_ip(tmp_path):
    data = dict(VALID, dns_whitelist=["999.999.1.1"])
    with pytest.raises(cfg.ConfigError, match="dns_whitelist.*非法 IP"):
        cfg.load(write_cfg(tmp_path, data))


def test_dns_whitelist_wrong_type(tmp_path):
    data = dict(VALID, dns_whitelist="203.0.113.10")
    with pytest.raises(cfg.ConfigError, match="dns_whitelist"):
        cfg.load(write_cfg(tmp_path, data))
