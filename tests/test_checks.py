"""Check-evaluation tests: confirmation window + unreachable escalation."""
import pytest

from core import checks as chk
from core import policy as pol


def local_ok():
    return {"mihomo_alive": True, "tun_present": True, "fakeip_ok": True}


def test_counter_rejects_invalid_config():
    with pytest.raises(ValueError):
        chk.CheckCounter(0, 5)
    with pytest.raises(ValueError):
        chk.CheckCounter(3, 0)


def test_pass_confirmed_only_after_n_consecutive():
    c = chk.CheckCounter(3, 5)
    for _ in range(2):
        assert chk.evaluate(local_ok(), pol.CLEAN, c) == "HOLD"
    assert chk.evaluate(local_ok(), pol.CLEAN, c) == "PASS_CONFIRMED"


def test_local_check_failure_is_block_now():
    c = chk.CheckCounter(3, 5)
    assert chk.evaluate({"mihomo_alive": True, "tun_present": True, "fakeip_ok": False},
                        pol.CLEAN, c) == "BLOCK_NOW"
    assert c.pass_streak == 0


def test_unreachable_resets_pass_streak_but_holds():
    c = chk.CheckCounter(3, 5)
    chk.evaluate(local_ok(), pol.CLEAN, c)
    chk.evaluate(local_ok(), pol.CLEAN, c)
    assert chk.evaluate(local_ok(), pol.UNREACHABLE, c) == "HOLD"
    assert c.pass_streak == 0


def test_unreachable_threshold_escalates():
    c = chk.CheckCounter(3, 5)
    for _ in range(4):
        assert chk.evaluate(local_ok(), pol.UNREACHABLE, c) == "HOLD"
    assert chk.evaluate(local_ok(), pol.UNREACHABLE, c) == "BLOCK_NOW"
    assert c.unreachable_streak == 0  # reset after escalation


def test_dirty_is_block_now_any_time():
    c = chk.CheckCounter(3, 5)
    chk.evaluate(local_ok(), pol.CLEAN, c)
    assert chk.evaluate(local_ok(), pol.DIRTY, c) == "BLOCK_NOW"
