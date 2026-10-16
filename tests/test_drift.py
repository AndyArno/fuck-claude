"""Drift detection diff tests (D-1/D-2)."""
from core import drift


def test_no_drift_when_all_covered():
    r = drift.detect_drift(
        dns_answers=["160.79.104.10"],
        ripe_prefixes=["160.79.104.0/23"],
        blocked_cidrs=["160.79.104.0/23"],
    )
    assert not r.drift_detected
    assert r.details == []


def test_doh_answer_outside_cidrs_detected():
    r = drift.detect_drift(
        dns_answers=["203.0.113.5"],
        ripe_prefixes=["160.79.104.0/23"],
        blocked_cidrs=["160.79.104.0/23"],
    )
    assert r.drift_detected
    assert r.doh_outside_cidrs == ("203.0.113.5",)
    assert any("203.0.113.5" in d for d in r.details)


def test_ripe_new_prefix_detected():
    r = drift.detect_drift(
        dns_answers=[],
        ripe_prefixes=["160.79.104.0/23", "160.79.106.0/24"],
        blocked_cidrs=["160.79.104.0/23"],
    )
    assert r.drift_detected
    assert r.ripe_new_prefixes == ("160.79.106.0/24",)


def test_ripe_missing_prefix_detected():
    r = drift.detect_drift(
        dns_answers=[],
        ripe_prefixes=["160.79.104.0/24"],
        blocked_cidrs=["160.79.104.0/23"],
    )
    assert r.drift_detected
    assert r.ripe_missing_prefixes == ("160.79.104.0/23",)


def test_v6_cidrs_supported():
    r = drift.detect_drift(
        dns_answers=["2607:6bc0:99::1"],
        ripe_prefixes=[],
        blocked_cidrs=["2607:6bc0::/48", "2607:6bc0:11::/48"],
    )
    assert r.drift_detected
    assert r.doh_outside_cidrs == ("2607:6bc0:99::1",)


def test_equivalent_cidr_not_flagged():
    r = drift.detect_drift(
        dns_answers=[],
        ripe_prefixes=["160.79.104.0/23"],
        blocked_cidrs=["160.79.104.0/23"],  # normalized identical
    )
    assert not r.drift_detected
