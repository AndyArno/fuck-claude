"""Check verdict interpretation and confirmation-window counting (pure logic).

Implements G-1/G-3 (confirmation window) and G-4 (three-way split:
DIRTY blocks immediately, UNREACHABLE counts toward escalation).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckOutcome:
    """单轮慢路径判定结果（传给状态机/计数的纯数据）。

    verdict: echo/DNS 综合三分法结果 'CLEAN' / 'DIRTY' / 'UNREACHABLE'。
      UNREACHABLE 中断放行确认窗、计入不可达升级计数（不等于看到脏）；
      DIRTY 混入任一探针即视为脏，立即升级阻断。
    dirty: 快路径等级的硬失败（本地检查 ①② 失败）→ 立即 BLOCK_NOW。
    """
    verdict: str = "CLEAN"
    dirty: bool = False


class CheckCounter:
    """确认窗计数器：放行通过连击 + 连续不可达升级计数。

    - pass_streak：连续 CLEAN 次数，达到 pass_confirm_count → PASS_CONFIRMED。
      DIRTY/硬失败 reset 且立即 BLOCK_NOW；UNREACHABLE 中断确认窗
      （pass_streak 清零）并累计不可达。
    - unreachable_streak：连续 UNREACHABLE 次数，达到
      fail_unreachable_threshold → BLOCK_NOW（fail-closed：探不到 ≠ 环境正常）。
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
