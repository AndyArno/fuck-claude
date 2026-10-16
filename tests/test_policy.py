"""Policy tests: CLEAN/DIRTY/UNREACHABLE three-way classification."""
import pytest

from core import policy as pol


def test_clean_ip_in_whitelist():
    assert pol.classify("203.0.113.10", ["203.0.113.10"]) == pol.CLEAN


def test_clean_cidr_whitelist():
    assert pol.classify("203.0.113.5", ["203.0.113.0/24"]) == pol.CLEAN


def test_dirty_ip_outside_whitelist():
    assert pol.classify("203.0.113.9", ["203.0.113.10"]) == pol.DIRTY


def test_dirty_blocks_even_on_first_probe():
    # G-4: first dirty sighting already classifies DIRTY (no tolerance)
    assert pol.classify("1.2.3.4", ["203.0.113.10"]) == pol.DIRTY


def test_unreachable_when_probe_result_none():
    assert pol.classify(None, ["203.0.113.10"]) == pol.UNREACHABLE


def test_malformed_response_is_dirty():
    assert pol.classify("not-an-ip", ["203.0.113.10"]) == pol.DIRTY
    assert pol.classify("", ["203.0.113.10"]) == pol.DIRTY


def test_ipv6_address_classified():
    assert pol.classify("2607:6bc0::1", ["2607:6bc0::/48"]) == pol.CLEAN
    assert pol.classify("2607:6bc0::1", ["203.0.113.10"]) == pol.DIRTY


def test_empty_whitelist_never_clean():
    assert pol.classify("203.0.113.10", []) == pol.DIRTY


def test_whitespace_stripped():
    assert pol.classify("  203.0.113.10  ", ["203.0.113.10"]) == pol.CLEAN
