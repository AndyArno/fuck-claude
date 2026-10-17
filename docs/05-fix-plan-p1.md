# 05 — P1 级问题修复方案（2026-10-16）

配套文档：`docs/04-audit-2026-10.md`（发现清单与证据）。本文档只覆盖 4 个 P1 级问题，
每项给出：根因 → 方案决策（含被否决的备选）→ 精确代码改动 → 测试计划 → 验证步骤 → 风险。

实施顺序建议：**P1-1 → P1-3 → P1-2 → P1-4**（P1-1 无依赖立即止血；P1-3 改动面小；
P1-2 涉并发语义需最后细做；P1-4 测试基建可并行但合入放最后，避免掩盖前三个的回归信号）。
每项完成后必跑 `.venv/Scripts/python -m pytest tests/ -q`（基线 209 passed）。

---

## P1-1 `tooltip()` NameError —— 托盘状态展示链路修复

### 根因
`b47c09b` 将 DNS 检查行改三态渲染时删除了 `summary = " ".join(parts)`，但
`core/messages.py:120-121` 仍引用 `summary`。每次调用必抛 `NameError`，
异常被 `tray.py:195-199 _event_loop` 的裸 `except: pass` 吞掉 → 托盘 title/菜单/详情窗
全部冻结在启动状态。测试无 `tooltip()` 覆盖。

### 方案决策
两步走：**先补回变量（止血），再给吞异常处加日志（防复发）**。
- 否决"在 `tooltip()` 内 try/except 兜底返回 head"——症状掩盖，违反本项目
  "文案错误应当暴露"的调试传统；正确做法是让异常有日志可见。
- `_event_loop` 保留 catch-all（UI 更新失败确实不应杀托盘线程），但从静默改为记日志。

### 代码改动

**① `core/messages.py`（tooltip 函数，:118-121）**
```python
    parts = [f"{label}{'✓' if v is True else '✗' if v is False else '–'}"
             for label, v in pairs]
    summary = " ".join(parts)                    # ← 补回此行
    if len(head) + len(summary) + 1 <= 120:
        return f"{head}\n{summary}"
    return head
```

**② `tray.py`（`_event_loop`，:195-199）**
```python
            try:
                self._apply(evt)
            except Exception:
                log.exception("托盘状态应用失败（UI 冻结防护，事件已丢弃）")
```
`tray.py` 顶部若尚无 logger，加 `log = logging.getLogger("claude_guard.tray")`
（复用 guardian 统一 logging 配置；`setup_logging` 按 root/命名 logger 挂 handler，
命名 logger 自动继承，无需额外接线——实施时确认 handler 传播链）。

### 测试计划
新增 `tests/test_messages.py`（或并入现有 messages 测试文件，跟随仓库惯例）：
- `test_tooltip_renders_all_states`：构造 5 组代表性 `Status`（blocking+原因行 /
  放行+出口行 / paused / override 中 / 全 None 未探测），断言返回 `str` 且不抛异常；
  断言三态渲染各出现一次（`✓`/`✗`/`–`）。
- `test_tooltip_truncation`：构造超长 reason 使 `len(head)+len(summary)+1 > 120`，
  断言降级返回 `head`（不含第三行）；边界值 ±1 各一例。
- `test_tray_apply_survives_bad_event`（tray 侧）：monkeypatch 使 `evt.tooltip()` 抛异常，
  调 `_apply` 断言不向上抛且 `_last_event` 已更新（事件不被完全丢弃的语义固定下来）。

### 验证
1. `pytest tests/ -q` 全绿。
2. 实机：`scripts/run_guardian.py` 开发态跑 1 分钟，悬停托盘确认 title 为
   "状态行+原因/出口行+检查摘要"三段；右键菜单点"暂停守护"观察 ✔ 即时出现
   （验证 `update_menu()` 链路复活）。

### 风险
极低。改动为纯文案函数补变量 + 日志行；无状态机/防火墙路径涉及。

---

## P1-3 `set_blocking` 动词 `-ErrorAction Stop` —— CG-FakeIP 缺失时放行/暂停失效

### 根因
`winplat/firewall.py:189-204` 的 PS 脚本：
`{verb}-NetFirewallRule -DisplayName @('CG-Global','CG-FakeIP') -ErrorAction Stop`。
数组中任一 DisplayName 未命中时，Stop 把非终止错误升级为终止错误 → 脚本非零退出 →
`_run_ps` 抛 `FirewallError` → `len(states) < 2 → return`（disable 幂等）分支
被前置短路**永不可达**。复查语义（数组 Get + `states` 比对）本身已能正确判缺失
（已实测：Get 部分缺失时 SilentlyContinue 只返回找到的规则、不抛错），
动词的 Stop 是冗余且有害的。

### 方案决策
**去掉动词上的 `-ErrorAction Stop`，缺失名容错交给复查层**，语义对齐 `block_all`。
- 否决"先逐个 get_status 再逐条操作"——回到多次 PS 进程，每次付 ~2.5s NetSecurity
  加载税，正是 `set_blocking`/`block_all` 单进程化要消灭的 7.7s。
- 否决"保留 Stop 但把数组拆成逐名循环"——同样语义但脚本更复杂；复查层已足够。

### 代码改动

**`winplat/firewall.py`（`set_blocking`）**
```python
    script = (
        "Import-Module NetSecurity;"
        # 动词不带 -ErrorAction Stop：数组中缺失的 DisplayName 只产生非终止
        # 错误（cmdlet 继续处理其余名），缺失判定由下方复查承担。
        f"{verb}-NetFirewallRule -DisplayName @({n1},{n2});"
        f"(Get-NetFirewallRule -DisplayName @({n1},{n2})"
        " -ErrorAction SilentlyContinue)"
        " | ForEach-Object { Write-Output ([string]$_.Enabled) }"
    )
    out = _run_ps(script)
    states = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
```
**复查逻辑同步收紧**（现 `len(states) < 2` 假设两条都应存在，需按方向区分）：
- `blocking=True`：CG-Global 必须存在且 Enabled。`states` 为空或首个对应
  CG-Global 的状态非 True → 抛 `FirewallError`（heal 线程 `ensure_exists` 重建兜底，
  fail-closed 方向不变）。CG-FakeIP 缺失可接受（无 fake-ip 集合时本就不存在）。
- `blocking=False`：所有**实际存在**的规则均为 False 即成功；`states` 为空
  （两条都不存在）= 幂等成功。维持现语义。

注意坑（AGENTS.md 已录）：动词对不存在规则 exit 0 假成功——所以**不能**只看
`_run_ps` 不抛错就返回，必须保留 `states` 逐值比对。本方案只动 ErrorAction，
复查强度不降。

### 测试计划（`tests/test_firewall.py`，离线喂 PS 输出，不发真 PS）
- `test_set_blocking_disable_fakeip_missing`：monkeypatch `_run_ps` 返回单行
  `"False"`（CG-FakeIP 不存在）→ 断言不抛（幂等放行）。
- `test_set_blocking_enable_fakeip_missing`：返回单行 `"True"` → 断言不抛
  （CG-Global 已阻断即达标）；返回空串 → 断言抛 `FirewallError`（CG-Global 缺失）。
- `test_set_blocking_partial_failure`：返回 `["False","True"]`（enable 后 CG-FakeIP
  仍 Disabled）→ 断言抛 `FirewallError`（复查强度不变的回归锚）。
- 脚本内容断言：生成脚本不含 `-ErrorAction Stop`、含数组字面量、不含 `-Protocol`。

### 验证
1. `pytest tests/ -q` 全绿。
2. 管理员窗口实机（改动 firewall.py 后的硬性要求）：
   - 先 `Remove-NetFirewallRule -DisplayName 'CG-FakeIP'` 制造缺失态；
   - `scripts/run_guardian.py` 启动 → 等环境判 CLEAN 转 ALLOWED（触发
     `set_blocking(False)`）→ `Get-NetFirewallRule -DisplayName 'CG-Global'`
     确认 Disabled 且日志无重试全败；
   - 点"暂停守护"→ `set_blocking(True)` → 确认 CG-Global Enabled；
   - 恢复后跑 `scripts/smoke_fw.py` 全量冒烟。

### 风险
低。改动方向是放宽动词错误处理、复查不变；唯一新假设"动词对缺失名产生非终止错误
且继续处理其余名"与模块内 `enable()` docstring 记载的实测行为一致。实机验证覆盖。

---

## P1-2 EXIT 与 rule-heal 线程竞态 —— T-6 防线的时序闭合

### 根因
`guardian.py` exit/pause 分支在主循环持 `_fw_lock` 执行 `block_all`/`set_blocking(True)`
**之后**才 `_stop.set()`（exit 在 :797-799，stop 在副作用之后）。heal 线程一轮自愈
若已在飞行中：它按旧 `_gstate` 算出 `expected_enabled=False`（:643-646），
其 `get_status` 在锁上排在 `block_all` 之后 → 读到 Enabled ≠ 期望 →
`_fw_tolerant("disable")`（:672）/`disable_fakeip`（:707）把刚恢复的阻断关掉。
随后 `os._exit(0)` 杀透进程，规则终态 Disabled。pause 路径同理（heal 反向关
`set_blocking(True)` 的结果——但 pause 期间主循环还活着，下轮 heal 会按
`paused` 期望 Enabled 纠正回来，所以**真正不可恢复的只有 exit**；pause 定级可降，
但同一修复一并覆盖）。

### 方案决策
双闸门，缺一不可：
1. **先置停，后副作用**：exit/pause 分支把 `self._stop.set()` 提到
   `block_all`/`set_blocking` **之前**。heal 主循环 `while not self._stop.is_set()`
   使"尚未开始"的轮次直接终止。
2. **写入前重检**：`_self_heal_rules` / `_heal_fakeip` 在**每个纠正性写入调用前**
   重检 `self._stop.is_set()`，为真则放弃本轮纠正。覆盖"heal 已在飞行中、
   stop 刚置位"的残留窗口。

- 否决"exit 时先 join heal 线程"——heal 可能正阻塞在 10s 超时的 PS 调用里，
  join 会把退出延迟重新拉高（刚优化掉的 15.6s 问题回潮）。
- 否决"给 expected_enabled 加版本号/gstate 快照比对"——复杂度远高于 stop 重检，
  收益相同。
- 注意 `_fw_tolerant` 内部重试间隙也应检 stop（避免 stop 后还在重试写入）：
  在 `_fw_tolerant` 循环开头加 `if self._stop.is_set(): return False`。
  这同时给所有写入路径加了统一的退出闸门，是最小侵入点。

### 代码改动

**① `guardian.py` exit 分支（:793-799）**
```python
        elif cmd == "exit":
            # 需求 T-6：恢复 Enabled（阻断）后退出。
            # 先置停再副作用：heal 线程见 stop 即终止/放弃纠正，
            # 防止它按旧 gstate 期望把刚恢复的阻断重新 disable（竞态 P1-2）。
            self.log.info("收到 EXIT 命令：恢复阻断后退出")
            self._stop.set()
            self._fw_tolerant(
                "block_all",
                list(self._fakeip_rule_ips) if self._fakeip_rule_ips else None)
            return False
```
注意：`_stop.set()` 后 `_fw_tolerant` 循环开头的 stop 检查会立即 `return False`
——与①冲突。因此 `_fw_tolerant` 的 stop 检查需带豁免：**给 `block_all` 这类
"退出语义要求的最后一次写入"加 `final: bool = False` 参数**，`final=True` 时跳过
stop 检查。exit 分支调 `_fw_tolerant("block_all", ..., final=True)`。
pause 分支的 `set_blocking(True)` 不置 stop（pause 非退出），无需豁免。

**② `guardian.py` `_fw_tolerant`（:558-575）**
```python
    def _fw_tolerant(self, method, *args, retries=3, delay=0.5,
                     final=False, **kwargs):
        for attempt in range(1, retries + 1):
            if self._stop.is_set() and not final:
                return False  # 退出中：放弃非终结性写入（P1-2 闸门）
            ...
```

**③ `guardian.py` `_self_heal_rules` / `_heal_fakeip` 写入前重检**
在 `_self_heal_rules` 三处纠正写入（重建后 disable、enable/disable 纠正、
`_heal_fakeip` 调用点）与 `_heal_fakeip` 两处纠正写入前各加：
```python
            if self._stop.is_set():
                self.log.info("退出中，放弃本轮规则纠正")
                return
```
（`_fw_tolerant` 内已有统一闸门时，③属于防御纵深——heal 直接调用
`self.fw.ensure_enabled_v6` 等裸路径不受 `_fw_tolerant` 保护，且 CG-V6 方向
恒为 enable 无风险；③只需覆盖会执行 **disable** 的分支。）

### 测试计划（`tests/test_guardian.py`）
- `test_exit_sets_stop_before_block_all`：FakeFirewall 记录调用序列 +
  在 `block_all` 内断言 `g._stop.is_set()` 已为真（顺序断言）。
- `test_heal_aborts_correction_after_stop`：构造 heal 飞行中场景——
  gstate=ALLOWED（期望 disable），先 `g._stop.set()` 再直接调
  `_self_heal_rules()`，断言 FakeFirewall 未收到 `disable`/`disable_fakeip`。
- `test_fw_tolerant_skips_writes_after_stop`：stop 置位后调
  `_fw_tolerant("disable")` → 断言 fw 零调用、返回 False；
  `_fw_tolerant("block_all", final=True)` → 断言 fw 收到调用。
- 时序回归：现有 exit/pause 用例（209 条内含）必须全绿，确认 stop 提前
  不破坏托盘退出推送顺序。

### 验证
1. `pytest tests/ -q` 全绿。
2. 实机竞态复现尝试（概率性，做 3-5 次）：放行态下点"退出（恢复阻断）"，
   退出后立即 `Get-NetFirewallRule -DisplayName 'CG-Global','CG-FakeIP'`
   确认均 Enabled；日志确认无 "纠正中" 发生在 block_all 之后。
3. pause 路径：暂停 → 日志确认规则 Enabled → 恢复 → 行为不变。

### 风险
中低。`final` 参数是新语义，需保证只有 exit 的 `block_all` 使用；
stop 提前置位后主循环 `run()` 的退出路径（`_stop.wait` 唤醒）行为不变
（stop 本就是退出信号，提前几百毫秒置位无影响）。drift-monitor 线程
见 stop 退出，无副作用。

---

## P1-4 防火墙失败路径测试真空 —— 把最重 fail-open 链路纳入回归

### 根因
三处权威路径零（有效）覆盖：
1. `set_blocking` 真实实现是"单 PS 原子切换+数组复查"，`tests/test_guardian.py:54-63`
   的 FakeFirewall 把它拆成顺序 `enable→enable_fakeip` / `disable→disable_fakeip`，
   且 fake 的 `enable_fakeip` 在规则缺失时抛 `RuntimeError`——真实 `disable_fakeip`
   对 MISSING 幂等成功。`test_fast_fail_blocks_immediately` 的断言由部分写入假绿。
2. `_fw_tolerant` 重试 3 次耗尽静默 `return False`：无任何用例注入持续失败，
   "已迁移 BLOCKED 但规则未启用 + heal 同因无法纠正"链路不可达、无告警验证。
3. `ensure_enabled_v6` 的 MISSING→重建 / DISABLED→强制 Enabled 分支零脚本级断言；
   `get_status_v6` 是死接口（仅定义无调用方）。

### 方案决策
三层补测，全部离线（喂 PS 输出文本 / fake 注入，不发真 PS、不碰真防火墙）：
1. **脚本级**：`tests/test_firewall.py` 对 `set_blocking`/`ensure_enabled_v6`
   补 PS 输出驱动的离线断言（与 P1-3 测试合并设计，见上节）。
2. **fake 对齐**：重写 FakeFirewall 的 `set_blocking` 为单次原子记录
   （`self.blocking_state = blocking` + 一条调用日志），`enable_fakeip` 对
   MISSING 改幂等（对齐真实 `disable_fakeip` 语义）。审查受影响用例：
   `test_fast_fail_blocks_immediately` 需改断言目标（从"enable 被调"改为
   "blocking_state 为阻断 + CG-Global enabled"）。
3. **持续失败注入**：新增可控失败的 FakeFirewall 模式
   （`fail_methods={"set_blocking": FirewallError("denied")}` 之类），
   用例：FAST_FAIL 迁移时 `set_blocking` 持续失败 → 断言状态机仍迁移到
   BLOCKED、`_fw_tolerant` 返回 False 且日志含"重试 3 次均失败"、
   随后触发 heal → heal 同因失败 → 规则期望未被放弃（下轮 heal 仍尝试）。
   同时暴露设计缺口：**该场景当前无任何用户可见告警**——方案为
   `_fw_tolerant` 耗尽且动作是 ENABLE 类时追加一条 error 级日志 +
   （可选）托盘 Toast 告警"防火墙操作持续失败，请检查管理员权限"。
   Toast 部分建议单开任务，不与本批混改。
4. **死接口清理**：`get_status_v6` 全仓无调用方 → 删除（firewall.py 定义 +
   FakeFirewall 定义），或保留并加调用方。建议删除（contract：无 shim 无死代码）。

### 测试计划汇总（新增/修改用例清单）
| 用例 | 文件 | 类型 |
|---|---|---|
| `test_set_blocking_*`（4 条，见 P1-3） | test_firewall.py | 新增 |
| `test_ensure_enabled_v6_missing_recreates` | test_firewall.py | 新增 |
| `test_ensure_enabled_v6_disabled_enables` | test_firewall.py | 新增 |
| `test_ensure_enabled_v6_enabled_noop` | test_firewall.py | 新增 |
| FakeFirewall 原子化 + `enable_fakeip` 幂等 | test_guardian.py | 修改 |
| `test_fast_fail_blocks_immediately` 断言目标修正 | test_guardian.py | 修改 |
| `test_fw_tolerant_exhaustion_keeps_blocking_intent` | test_guardian.py | 新增 |
| `test_heal_persistent_failure_retries_next_round` | test_guardian.py | 新增 |
| `get_status_v6` 删除连带清理 | firewall.py / test_guardian.py | 修改 |

### 验证
1. `pytest tests/ -q` 全绿（用例数应 ≥ 209 + 新增）。
2. 变异自检：临时把 `set_blocking` 复查改回弱断言（如只查空输出），
   确认新增的 partial_failure 用例变红——证明断言有牙。

### 风险
低（纯测试 + 一处死代码删除）。唯一行为面变化：fake 语义修正可能暴露
既有用例中依赖旧 fake 行为的隐藏假设——暴露即修，属于本项的目的。

---

## 附：四项改动文件清单

| 文件 | P1-1 | P1-2 | P1-3 | P1-4 |
|---|---|---|---|---|
| `core/messages.py` | ✎ | | | |
| `tray.py` | ✎（日志） | | | |
| `guardian.py` | | ✎（exit 分支、`_fw_tolerant`、heal 重检） | | |
| `winplat/firewall.py` | | | ✎（`set_blocking`） | ✎（删 `get_status_v6`） |
| `tests/test_messages.py` | ✚ | | | |
| `tests/test_firewall.py` | | | ✚ | ✚ |
| `tests/test_guardian.py` | | ✚ | | ✚/✎ |

提交建议拆 4 个 commit（一 P1 一 commit），信息格式遵 AGENTS.md：
`<类型>(<范围>): <描述>——<关键实测证据>`。firewall.py 涉及的两项（P1-3/P1-4）
合并实机验证一次即可（`net session` 探管理员 + `smoke_fw.py`）。
