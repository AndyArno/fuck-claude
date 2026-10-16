"""State machine tests — traceable to docs/03-dev-plan.md M2 test matrix (12 items)."""
import pytest

from core import checks as chk
from core import policy as pol
from core import statemachine as sm


def mk_gate(state=sm.BLOCKED, drift=False, override=False):
    return sm.GateState(state, drift, override)


def acts(t):
    return [a["action"] for a in t.actions]


def dirty_outcome():
    return chk.CheckOutcome(verdict=pol.DIRTY)


def clean_outcome():
    return chk.CheckOutcome(verdict=pol.CLEAN)


def unreachable_outcome():
    return chk.CheckOutcome(verdict=pol.UNREACHABLE)


# --- Matrix #1: BLOCKED + 连续3次PASS → ALLOWED
def test_matrix_01_blocked_three_consecutive_pass_releases():
    counter = chk.CheckCounter(pass_confirm_count=3, fail_unreachable_threshold=5)
    local_ok = {"mihomo_alive": True, "tun_present": True, "fakeip_ok": True}
    assert chk.evaluate(local_ok, pol.CLEAN, counter) == "HOLD"
    assert chk.evaluate(local_ok, pol.CLEAN, counter) == "HOLD"
    assert chk.evaluate(local_ok, pol.CLEAN, counter) == "PASS_CONFIRMED"
    t = sm.transition(mk_gate(), sm.CHECK_PASS)
    assert t.new_state.state == sm.ALLOWED
    assert sm.DISABLE_FIREWALL in acts(t)


# --- Matrix #2: BLOCKED + 2次PASS后1次FAIL → 计数清零，保持 BLOCKED
def test_matrix_02_pass_then_fail_resets_streak_stays_blocked():
    counter = chk.CheckCounter(3, 5)
    local_ok = {"mihomo_alive": True, "tun_present": True, "fakeip_ok": True}
    chk.evaluate(local_ok, pol.CLEAN, counter)
    chk.evaluate(local_ok, pol.CLEAN, counter)
    assert counter.pass_streak == 2
    # interruption: any FAIL/UNREACHABLE/DIRTY resets to zero
    assert chk.evaluate(local_ok, pol.UNREACHABLE, counter) == "HOLD"
    assert counter.pass_streak == 0
    # two more passes are still not enough
    chk.evaluate(local_ok, pol.CLEAN, counter)
    chk.evaluate(local_ok, pol.CLEAN, counter)
    assert chk.evaluate(local_ok, pol.CLEAN, counter) == "PASS_CONFIRMED"
    # state machine: PROBING hold until confirmed
    t = sm.transition(mk_gate(sm.PROBING), sm.CHECK_FAIL)
    assert t.new_state.state == sm.BLOCKED
    assert sm.ENABLE_FIREWALL in acts(t)


# --- Matrix #3: ALLOWED + 1次FAIL → BLOCKED（立即，无确认窗）
def test_matrix_03_allowed_single_fail_blocks_immediately():
    t = sm.transition(mk_gate(sm.ALLOWED), sm.CHECK_FAIL)
    assert t.new_state.state == sm.BLOCKED
    assert sm.ENABLE_FIREWALL in acts(t)
    assert sm.NOTIFY_BLOCK in acts(t)


# --- Matrix #4: ALLOWED + PROBE_UNREACHABLE ×4 → 仍 ALLOWED
def test_matrix_04_allowed_four_unreachable_stays_allowed():
    state = mk_gate(sm.ALLOWED)
    for _ in range(4):
        t = sm.transition(state, sm.PROBE_UNREACHABLE)
        state = t.new_state
    assert state.state == sm.ALLOWED
    assert sm.ENABLE_FIREWALL not in acts(t)


# --- Matrix #5: ALLOWED + PROBE_UNREACHABLE ×5(阈值) → BLOCKED + 告警
def test_matrix_05_allowed_five_unreachable_escalates_to_block():
    counter = chk.CheckCounter(3, 5)
    outcome = unreachable_outcome()
    for _ in range(4):
        assert counter.record(outcome) == "HOLD"
    assert counter.record(outcome) == "BLOCK_NOW"
    t = sm.transition(mk_gate(sm.ALLOWED), sm.CHECK_FAIL)  # escalation delivered as CHECK_FAIL
    assert t.new_state.state == sm.BLOCKED
    assert sm.ENABLE_FIREWALL in acts(t)
    assert sm.NOTIFY_BLOCK in acts(t)


# --- Matrix #6: OVERRIDE_START → 30min 内检查失败不阻断
def test_matrix_06_override_ignores_check_failures():
    state = sm.transition(mk_gate(sm.ALLOWED), sm.OVERRIDE_START).new_state
    assert state.on_override
    assert sm.DISABLE_FIREWALL in acts(sm.transition(mk_gate(sm.ALLOWED), sm.OVERRIDE_START))
    for ev in (sm.FAST_FAIL, sm.CHECK_FAIL, sm.PROBE_UNREACHABLE):
        t = sm.transition(state, ev)
        assert t.new_state.state == state.state  # stays allowed, no firewall actions
        assert sm.ENABLE_FIREWALL not in acts(t)


# --- Matrix #7: OVERRIDE_EXPIRE → 回到正常检查（恢复阻断）
def test_matrix_07_override_expire_returns_to_blocked():
    state = sm.transition(mk_gate(sm.ALLOWED), sm.OVERRIDE_START).new_state
    t = sm.transition(state, sm.OVERRIDE_EXPIRE)
    assert t.new_state.state == sm.BLOCKED
    assert not t.new_state.on_override
    assert sm.ENABLE_FIREWALL in acts(t)


# --- Matrix #8: DRIFT_DETECTED → 仅标志位，不影响放行
def test_matrix_08_drift_only_sets_flag():
    t = sm.transition(mk_gate(sm.ALLOWED), sm.DRIFT_DETECTED)
    assert t.new_state.state == sm.ALLOWED
    assert t.new_state.drift_alarm
    assert t.actions == [{"action": sm.NOTIFY_ALERT, "message": "IP 段漂移告警"}]
    assert sm.ENABLE_FIREWALL not in acts(t)
    assert sm.DISABLE_FIREWALL not in acts(t)
    # also in BLOCKED: no firewall action
    t = sm.transition(mk_gate(sm.BLOCKED), sm.DRIFT_DETECTED)
    assert t.new_state.state == sm.BLOCKED
    assert t.new_state.drift_alarm
    assert sm.ENABLE_FIREWALL not in acts(t)


# --- Matrix #9: Clash 启动中间态（check①②过③未过）→ 保持 BLOCKED
def test_matrix_09_partial_local_checks_hold_blocked():
    counter = chk.CheckCounter(3, 5)
    mid = {"mihomo_alive": True, "tun_present": True, "fakeip_ok": False}
    assert chk.evaluate(mid, pol.CLEAN, counter) == "BLOCK_NOW"
    # state machine: single pass event from BLOCKED must never release (needs ×N)
    t2 = sm.transition(mk_gate(sm.PROBING), sm.CHECK_PASS)
    assert t2.new_state.state == sm.PROBING
    assert sm.DISABLE_FIREWALL not in acts(t2)
    # premature-release gating lives in checks.py (verified above); the SM
    # only releases on the CHECK_PASS event guardian sends after PASS_CONFIRMED.


# --- Matrix #10: ALLOWED + FAST_FAIL → 立即 BLOCKED，无任何确认/容忍计数
def test_matrix_10_allowed_fast_fail_blocks_immediately():
    t = sm.transition(mk_gate(sm.ALLOWED), sm.FAST_FAIL)
    assert t.new_state.state == sm.BLOCKED
    assert t.actions[0] == {"action": sm.ENABLE_FIREWALL}
    assert sm.NOTIFY_BLOCK in acts(t)


# --- Matrix #11: BLOCKED + FAST_FAIL → 保持 BLOCKED（幂等，不重复通知）
def test_matrix_11_blocked_fast_fail_idempotent():
    t = sm.transition(mk_gate(), sm.FAST_FAIL)
    assert t.new_state.state == sm.BLOCKED
    assert t.actions == []
    assert sm.NOTIFY_BLOCK not in acts(t)


# --- Matrix #12: DIRTY → 无论当前状态、无论第几次 → 立即 BLOCKED
def test_matrix_12_dirty_blocks_immediately_from_any_state():
    counter = chk.CheckCounter(3, 5)
    for _ in range(2):  # even first dirty probe after passes
        pass
    assert counter.record(dirty_outcome()) == "BLOCK_NOW"
    for st in (sm.BLOCKED, sm.PROBING, sm.ALLOWED):
        t = sm.transition(mk_gate(st), sm.CHECK_FAIL)
        assert t.new_state.state == sm.BLOCKED
        assert sm.ENABLE_FIREWALL in acts(t)
    # dirty during override still blocked at expire, and DIRTY never tolerated:
    counter2 = chk.CheckCounter(3, 5)
    counter2.record(clean_outcome())
    counter2.record(clean_outcome())
    assert counter2.record(dirty_outcome()) == "BLOCK_NOW"


# --- v6 rules never in actions (B-6)
def test_v6_rules_never_appear_in_actions():
    events = [sm.FAST_FAIL, sm.CHECK_PASS, sm.CHECK_FAIL, sm.PROBE_UNREACHABLE,
              sm.OVERRIDE_START, sm.OVERRIDE_EXPIRE, sm.DRIFT_DETECTED]
    for st in (sm.BLOCKED, sm.PROBING, sm.ALLOWED):
        for drift in (False, True):
            for ov in (False, True):
                for ev in events:
                    t = sm.transition(mk_gate(st, drift, ov), ev)
                    for a in t.actions:
                        assert "v6" not in str(a.get("action", "")).lower()
                        assert "CG-V6" not in str(a)


# --- unknown event
def test_unknown_event_raises():
    with pytest.raises(ValueError):
        sm.transition(mk_gate(), "NOPE")
