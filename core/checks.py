"""Check verdict interpretation and confirmation-window counting (pure logic).

Implements G-1/G-3 (confirmation window) and G-4 (three-way split:
DIRTY blocks immediately, UNREACHABLE counts toward escalation).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckOutcome:
    """Single slow-tick evaluation result handed to the state machine.

    check_results: per-check booleans, all must be True for a PASS.
      Keys: mihomo_alive, tun_present, fakeip_ok, echo (verdict string).
    verdict: 'CLEAN' / 'DIRTY' / 'UNREACHABLE' for the echo probe.
    dirty: True when any visible check failed outright (fast-path style).
    """
    verdict: str = "CLEAN"
    dirty: bool = False


class CheckCounter:
    """Confirmation-window pass counter + consecutive-unreachable counter.

    - pass streak must reach pass_confirm_count consecutively; any
      interruption (FAIL/DIRTY/UNREACHABLE reset per G-3 semantics:
      only a hard DIRTY/FAIL blocks immediately, UNREACHABLE preserves
      the pass streak? No — spec says interruption resets) resets to 0.
    - unreachable streak: fail_unreachable_threshold consecutive
      UNREACHABLE verdicts escalate to block.
    """

    def __init__(self, pass_confirm_count: int, fail_unreachable_threshold: int) -> None:
        if pass_confirm_count < 1:
            raise ValueError("pass_confirm_count 必须 >= 1")
        if fail_unreachable_threshold < 1:
            raise ValueError("fail_unreachable_threshold 必须 >= 1")
        self.pass_confirm_count = pass_confirm_count
        self.fail_unreachable_threshold = fail_unreachable_threshold
        self._pass_streak = 0
        self._unreachable_streak = 0

    def reset(self) -> None:
        self._pass_streak = 0
        self._unreachable_streak = 0

    @property
    def pass_streak(self) -> int:
        return self._pass_streak

    @property
    def unreachable_streak(self) -> int:
        return self._unreachable_streak

    def record(self, outcome: CheckOutcome) -> str:
        """Record one slow-tick outcome; return 'BLOCK_NOW' | 'PASS_CONFIRMED' | 'HOLD'."""
        if outcome.dirty or outcome.verdict == "DIRTY":
            # G-4: dirty exit is seen with our own eyes → block immediately,
            # no tolerance, all streaks irrelevant.
            self.reset()
            return "BLOCK_NOW"

        if outcome.verdict == "UNREACHABLE":
            # G-4: cannot see ≠ saw dirty. Interrupts the pass confirmation
            # window (Clash mid-start state, matrix #2/#9) but only warns;
            # escalate to block after M consecutive unreachable probes.
            self._pass_streak = 0
            self._unreachable_streak += 1
            if self._unreachable_streak >= self.fail_unreachable_threshold:
                self.reset()
                return "BLOCK_NOW"
            return "HOLD"

        # CLEAN (and all local checks passed)
        self._unreachable_streak = 0
        self._pass_streak += 1
        if self._pass_streak >= self.pass_confirm_count:
            self._pass_streak = 0
            return "PASS_CONFIRMED"
        return "HOLD"


def evaluate(check_results: dict[str, bool], verdict: str,
             counter: CheckCounter) -> str:
    """Evaluate one slow-tick's four checks against the counters.

    check_results keys: mihomo_alive / tun_present / fakeip_ok.
    Local check failure (①②) means the proxy is dead/dying → dirty
    (fast-path equivalent, immediate block).
    Returns one of 'BLOCK_NOW' | 'PASS_CONFIRMED' | 'HOLD'.
    """
    local_ok = all(
        check_results.get(k, False) for k in ("mihomo_alive", "tun_present", "fakeip_ok")
    )
    if not local_ok:
        counter.reset()
        return "BLOCK_NOW"
    return counter.record(CheckOutcome(verdict=verdict, dirty=False))
