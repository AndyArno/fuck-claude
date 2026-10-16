"""Gate state machine (pure logic, no side effects).

States: BLOCKED / PROBING / ALLOWED, plus orthogonal DRIFT_ALARM flag.
transition(state, event) -> (new_state, actions) where actions is a list
of instruction dicts for the platform layer (firewall / notify).

v6 rules NEVER appear in actions: CG-V6 is permanently enabled and the
gate has no authority over it (B-6).
"""
from __future__ import annotations

from dataclasses import dataclass, field

BLOCKED = "BLOCKED"
PROBING = "PROBING"
ALLOWED = "ALLOWED"

FAST_FAIL = "FAST_FAIL"
CHECK_PASS = "CHECK_PASS"
CHECK_FAIL = "CHECK_FAIL"
PROBE_UNREACHABLE = "PROBE_UNREACHABLE"
OVERRIDE_START = "OVERRIDE_START"
OVERRIDE_EXPIRE = "OVERRIDE_EXPIRE"
DRIFT_DETECTED = "DRIFT_DETECTED"

ENABLE_FIREWALL = "firewall.enable"
DISABLE_FIREWALL = "firewall.disable"
NOTIFY_BLOCK = "notify.block"
NOTIFY_ALLOW = "notify.allow"
NOTIFY_ALERT = "notify.alert"

ALLOWED_EVENTS = frozenset({
    FAST_FAIL, CHECK_PASS, CHECK_FAIL, PROBE_UNREACHABLE,
    OVERRIDE_START, OVERRIDE_EXPIRE, DRIFT_DETECTED,
})


@dataclass(frozen=True)
class GateState:
    state: str = BLOCKED
    drift_alarm: bool = False
    on_override: bool = False

    def with_drift(self) -> "GateState":
        return GateState(self.state, True, self.on_override)


@dataclass(frozen=True)
class Transition:
    new_state: GateState
    actions: list[dict] = field(default_factory=list)


def transition(state: GateState, event: str) -> Transition:
    """Pure transition: returns new state + platform action instructions."""
    if event not in ALLOWED_EVENTS:
        raise ValueError(f"未知事件: {event!r}")

    # DRIFT_DETECTED is orthogonal: only sets the flag, never touches
    # firewall or release decisions (D-3, matrix #8).
    if event == DRIFT_DETECTED:
        if state.drift_alarm:
            return Transition(state)  # idempotent, no repeat notification
        return Transition(state.with_drift(), [{"action": NOTIFY_ALERT,
                                                "message": "漂移告警：封禁段覆盖可能失效"}])

    # Override is active: checks must not block (matrix #6). Only expiry
    # or a state-external force changes anything.
    if state.on_override and event in (FAST_FAIL, CHECK_FAIL, PROBE_UNREACHABLE):
        return Transition(state)

    if event == OVERRIDE_START:
        return Transition(GateState(state.state, state.drift_alarm, True),
                          [{"action": DISABLE_FIREWALL},
                           {"action": NOTIFY_ALLOW, "message": "临时放行开始"}])

    if event == OVERRIDE_EXPIRE:
        return Transition(GateState(BLOCKED, state.drift_alarm, False),
                          [{"action": ENABLE_FIREWALL},
                           {"action": NOTIFY_BLOCK, "message": "临时放行结束，已恢复阻断"}])

    if event == FAST_FAIL:
        if state.state == BLOCKED:
            # Matrix #11: idempotent, no repeated notify.
            return Transition(state)
        # Matrix #10: ALLOWED/PROBING + FAST_FAIL → immediate block,
        # no confirmation window, no tolerance.
        return Transition(GateState(BLOCKED, state.drift_alarm, False),
                          [{"action": ENABLE_FIREWALL},
                           {"action": NOTIFY_BLOCK, "message": "代理进程/TUN 消失，已立即阻断"}])

    if event == CHECK_FAIL:
        # DIRTY exit or local check failure: immediate block, no tolerance (G-4).
        return Transition(GateState(BLOCKED, state.drift_alarm, False),
                          [{"action": ENABLE_FIREWALL},
                           {"action": NOTIFY_BLOCK, "message": "检查失败，已阻断"}])

    if event == PROBE_UNREACHABLE:
        # Counting escalation happens in checks.py; the state machine only
        # sees the escalated event as CHECK_FAIL. A bare PROBE_UNREACHABLE
        # in ALLOWED keeps state (matrix #4); in BLOCKED/PROBING, hold.
        return Transition(state)

    if event == CHECK_PASS:
        if state.state == ALLOWED:
            return Transition(state)  # already allowed; no repeat notify
        if state.state == PROBING:
            return Transition(state)  # confirmation window managed by checks.py
        # BLOCKED + confirmed N consecutive passes → release (matrix #1).
        return Transition(GateState(ALLOWED, state.drift_alarm, False),
                          [{"action": DISABLE_FIREWALL},
                           {"action": NOTIFY_ALLOW, "message": "Claude 已放行"}])

    raise ValueError(f"事件 {event!r} 在状态 {state.state} 下未定义")  # pragma: no cover
