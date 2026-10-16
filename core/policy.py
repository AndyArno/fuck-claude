"""Probe-result classification (pure logic)."""
from __future__ import annotations

import ipaddress
from enum import Enum

CLEAN = "CLEAN"
DIRTY = "DIRTY"
UNREACHABLE = "UNREACHABLE"


class Verdict(str, Enum):
    CLEAN = CLEAN
    DIRTY = DIRTY
    UNREACHABLE = UNREACHABLE


def _entry_matches(entry: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return ip in net


def classify(probe_result: str | None, whitelist: list[str]) -> str:
    """Classify an echo-probe result.

    probe_result: the observed egress IP string, or None when the probe
    was unreachable (timeout / endpoint down).

    Returns CLEAN (IP in whitelist), DIRTY (a visible IP outside the
    whitelist — block immediately, no tolerance), or UNREACHABLE
    (cannot see; count toward escalation threshold).
    """
    if probe_result is None:
        return UNREACHABLE
    try:
        ip = ipaddress.ip_address(probe_result.strip())
    except ValueError:
        # Malformed response: we "saw" something but cannot trust it as clean.
        return DIRTY
    for entry in whitelist or []:
        if _entry_matches(entry, ip):
            return CLEAN
    return DIRTY
