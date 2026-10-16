"""Drift detection diff logic (pure logic, no side effects)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DriftReport:
    doh_outside_cidrs: tuple[str, ...] = ()      # resolved IPs not covered by blocked cidrs
    doh_new_ips: tuple[str, ...] = ()            # resolved IPs not seen in previous set
    ripe_new_prefixes: tuple[str, ...] = ()      # announced prefixes not in config
    ripe_missing_prefixes: tuple[str, ...] = ()  # config cidrs no longer announced
    drift_detected: bool = False
    details: list[str] = field(default_factory=list)


def _covers(cidrs: list[str], ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _cidr_set(cidrs: list[str]) -> set[str]:
    out = set()
    for c in cidrs:
        try:
            out.add(str(ipaddress.ip_network(c, strict=False)))
        except ValueError:
            continue
    return out


def detect_drift(dns_answers: list[str], ripe_prefixes: list[str],
                 blocked_cidrs: list[str]) -> DriftReport:
    """Compare DoH answers and RIPE announced prefixes against configured cidrs.

    dns_answers: IPs resolved via DoH for the claude domains.
    ripe_prefixes: prefixes currently announced by the ASN.
    blocked_cidrs: configured blocked cidrs (v4 or v6, caller decides).
    """
    doh_outside = tuple(ip for ip in dns_answers if not _covers(blocked_cidrs, ip))

    # An answer is "new" when it is not covered by any configured cidr,
    # i.e. the configured set no longer describes reality.
    doh_new = doh_outside

    ripe_set = {_norm(p) for p in ripe_prefixes if _norm(p)}
    config_set = _cidr_set(blocked_cidrs)
    ripe_new = tuple(sorted(ripe_set - config_set))
    ripe_missing = tuple(sorted(config_set - ripe_set))

    details: list[str] = []
    if doh_outside:
        details.append("DoH 解析结果不在封禁段内: " + ", ".join(doh_outside))
    if ripe_new:
        details.append("RIPE 新公告前缀: " + ", ".join(ripe_new))
    if ripe_missing:
        details.append("RIPE 已不公告的配置段: " + ", ".join(ripe_missing))

    drift = bool(doh_outside or ripe_new or ripe_missing)
    return DriftReport(
        doh_outside_cidrs=doh_outside,
        doh_new_ips=doh_new,
        ripe_new_prefixes=ripe_new,
        ripe_missing_prefixes=ripe_missing,
        drift_detected=drift,
        details=details,
    )


def _norm(p: str) -> str:
    try:
        return str(ipaddress.ip_network(p, strict=False))
    except ValueError:
        return ""
