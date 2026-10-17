# 07 — P3 级问题修复方案（2026-10-17）

配套：`docs/04-audit-2026-10.md` 第四节（发现清单）。前置：P1（157e3b6/697c9d1）、
netsh 快车道（a2ecbc6）、P2 全部（8106557/924d938/1f8be88/2e58167）已落地，基线 **288 passed**。

**已剔除**（前序批次已修，不再重复）：smoke `CREATE_NO_WINDOW`（P2-6）、`_geo_cache` 淘汰（P2-2）、
`get_status_v6` 死接口（P1-4）、AGENTS 计数/README 配置表/黄灯语义（P2 C 片）、
`policy.classify` CIDR 重复解析（审计结论"当前量级不建议改"，维持记录）。

分片原则：按文件归属避免并行冲突。A=guardian/tray/文案/checks；B=config/winplat 探测链；
C=纯文档。**跨片接口契约见 P3-18**（A 独享 messages.py，无跨片调用依赖）。

---

## A 片（guardian.py、tray.py、core/messages.py、core/checks.py、tests/test_guardian.py、tests/test_tray.py、tests/test_messages.py）

### P3-5 override 期间环境转净确认后重复弹"临时放行开始"Toast
- **根因**：override 从 BLOCKED 启动后慢路径继续，连续 CLEAN 触发 CHECK_PASS → NOTIFY_ALLOW；
  `_toast_text` 的 NOTIFY_ALLOW 分支按 `on_override` 标志（仍 True）误判为"临时放行开始"。
- **改动**：`_toast_text` NOTIFY_ALLOW 分支——`on_override` 且当前已处于放行动作重复场景时不再弹
  override_start。实现建议：`_apply_event` 调用 `_toast_text` 前记录 `old.state`；
  BLOCKED→ALLOWED 且 `on_override` → 用 `toast_allow()`（或不弹）。保持 override 首次启动
  （ALLOWED 态点 override / BLOCKED 态 OVERRIDE_START 动作）文案不变。
- **验收**：用例复现"override 中 CHECK_PASS 迁移"→ 断言不再发 toast_override_start；首次 override 仍发。

### P3-6 临时放行菜单标签 start 时固化
- **根因**：`tray.py:253` `self._override_label()` 以字符串求值一次，热重载 `override_minutes` 后不更新。
- **改动**：改传 callable：`pystray.MenuItem(self._override_label, ...)`（pystray 支持 text 为 callable）。
- **验收**：用例——构造 Tray、改 `_last_event.override_minutes`，断言菜单项文本求值跟随变化。

### P3-7 `core/checks.py` docstring 失实
- **改动**：重写 `CheckOutcome`/`CheckCounter` docstring——删不存在的 `check_results` 字段描述与
  开发自问碎句；明确"UNREACHABLE 中断确认窗、计入不可达计数；DIRTY 混入立即升级"。

### P3-11 bool 兼容死代码清理
- **根因**：生产 `get_status`/`get_status_fakeip` 恒返回 `RuleStatus` 三态；`guardian._self_heal_rules`
  与 `_heal_fakeip` 的"兼容旧 bool"分支、tests 的 `status_mode="bool"` 路径都是死代码。
- **改动**：删 guardian 两处 bool 兼容分支（保留三态处理）；删 `FakeFirewall.status_mode` 与
  相关用例/参数（tests/test_guardian.py:27-36、:96、:709 一带），fake 恒按三态。
- **验收**：全绿；grep 无 `status_mode` 残留。

### P3-12a selfcheck 检查⑤ 调用补 try/except
- **根因**：dnscheck 底层解析异常（如 P3-3 的 struct.error）在守护路径有兜底（UNREACHABLE），
  selfcheck 无 try 会直接 traceback。
- **改动**：selfcheck ⑤ 调用包 try/except → 输出"探测异常"并按不可达展示（不自判"已放行"）。
- **验收**：monkeypatch `check_dns_egress` 抛异常，断言 selfcheck 正常输出且退出码非 0（fail-closed）。

### P3-18 `--check` 分隔线前两条文案移入 messages.py
- **根因**：硬约束⑤（用户可见文案全部收敛 messages.py）字面口径；selfcheck 开头两条
  （"当前检查未见异常…"提示与"只读探测…"说明）硬编码于 guardian。
- **改动**：messages.py 新增 `selfcheck_intro() -> tuple[str, str]`；selfcheck 改调用。
  分隔线后的技术明细保持豁免不变。
- **验收**：用例断言 selfcheck 输出来自 messages 函数（monkeypatch 该函数返回值可观测传播）。

### P3-19 队列重复 exit 命令去重
- **根因**：实机日志（20:36:25）同毫秒两条 `命令开始 exit`，各付一次 PS 全量。
- **改动**：`_drain_commands` 遇到返回 False 的命令后立即返回（现状已如此）——问题在**重复入队**：
  `tray._menu_cb` 对 EXIT 命令做入队去重（如 EXIT 已在队列未消费则不再投），或 guardian drain 时
  先清空队列中冗余 exit。取实现更简单者，注释说明。
- **验收**：连投两条 exit → 日志/调用记录只执行一次 block_all。

### P3-20 FakeTray `_on_command` 正向分支零覆盖（TestsDocs L5）
- **改动**：补用例——托盘命令经 `_menu_cb` 路径（含 `_on_command` 唤醒回调）投递，断言
  commands 队列收到且唤醒被调用。

---

## B 片（core/config.py、winplat/netprobe.py、winplat/dnscheck.py、winplat/ripecheck.py、winplat/winmsg.py、tests/test_config.py、tests/test_netprobe_parsing.py、tests/test_dnscheck.py、tests/test_ripecheck.py（新建）、tests/test_winmsg.py（新建）、tests/test_firewall.py）

### P3-1 `dns_egress_countries` 校验放行全角字母
- **改动**：`core/config.py` 校验加 `x.isascii()`（全角"ＵＳ" isalpha 为 True 但永不匹配 ASCII 国家码）。
- **验收**：全角两字母 → ConfigError。

### P3-2 `blocked_cidrs_v6` 缺非空校验（与 v4 不对称）
- **改动**：补与 v4 相同的非空校验（B-1 对称；空列表时 `create_rule_v6` 生成 `@()` 行为未定义）。
- **验收**：空 v6 → ConfigError 且错误信息指名字段。

### P3-3 TXT 记录字符串数 ≥8 时 `_read_string_array` 越界
- **根因**：`_DnsRecordHead.Data` 只拷 64 字节，count<64 守卫过宽，i≥7 时 `unpack_from` 越界 struct.error。
- **改动**：优先按 `wDataLength` 截断/扩大拷贝（结构体已有该字段）；若实现复杂则收紧 `0 < count <= 7`
  并注释理由。二选一，以不发越界为准。
- **验收**：离线构造 count=8/63 样本 → 不抛 struct.error，行为符合所选语义。

### P3-4 trace 分发鲁棒性 + `TRACE_URL` 死常量
- **改动**：`probe_echo_endpoints` 分发前剥 query/fragment 并 lower（`.../cdn-cgi/trace?x=1`、大小写变体
  不再误走纯文本解析）；删 `TRACE_URL` 常量并更新 docstring。
- **验收**：带 query/大写路径的 URL 走 trace 解析；grep 无 TRACE_URL。

### P3-9 winmsg `LiveMessageBox.refresh` 标题不刷新
- **根因**：标题更新嵌在 `if text != self._text:` 内，正文不变标题变（如状态迁移但检查项相同）时不刷。
- **改动**：标题/正文各自判变分别更新；补 tests/test_winmsg.py（Win32 调用 mock）。
- **验收**：仅标题变化 → 标题更新被调用；无窗口（closed）→ no-op 不抛。

### P3-10 ripecheck 畸形 payload / fetch 异常零测试（TestsDocs L4）
- **改动**：tests/test_ripecheck.py——`parse_prefixes` 喂畸形 payload（缺 data/非 dict item/空 prefixes）；
  fetch 层 RequestException/超时/ValueError → ok=False 不炸。样本 CIDR 用文档段。
- **验收**：新增用例有行为断言；notify.py 零测试维持（daemon+全吞，审计已接受，docstring 注明即可）。

### P3-12b test_firewall 手工 save/restore 改 monkeypatch（TestsDocs L6）
- **改动**：`TestCreateRuleNoProtocolRestriction` 的 try/finally 改 monkeypatch（风格统一）。

---

## C 片（docs/01、docs/03、README.md、AGENTS.md）

### P3-D1 G-3"至少 N×探测周期才放行"与首轮即检矛盾（Docs L4）
- **改动**：docs/01 G-3 回写实际语义——"首轮即跑慢路径，放行需连续 N 次 CLEAN（启动最快 ~11s）"。

### P3-D2 dev-plan 5.4 卸载措辞（Docs L6）
- **改动**：docs/03 5.4 "删程序"改为与 uninstall.ps1/README 一致的表述（脚本删任务+规则，目录手动删）。

### P3-D3 README 托盘交互补全（Docs L9）
- **改动**：补左键双击开详情窗、override 期"立即恢复阻断"菜单项；T-3 清单对齐实现。

### P3-D4 AGENTS.md 测试计数
- **改动**：实测当前数更新（实施时跑全量；C 片最后提交，以当时实测为准）。

---

## 执行与核验

1. 三片并行，各自全量 pytest 绿后分片单 commit（中文格式）；**严禁改分片外文件**。
2. 主审查线核验：全量 pytest、逐片 diff 复核、抽样实机（本次无 firewall 行为改动，无需 smoke）。
3. **红线**：禁止真实 IP/网段入代码/测试/文档/提交；提交前 grep 自查（模式同 docs/06）。
4. notify.py 零测试维持现状（daemon+异常全吞，审计已接受）。

---

## 核验记录（2026-10-17，主审查线）

三片均已实施并提交：**A=629f3b0**（guardian/tray/messages/checks，新增 11 删 1）、
**B=463ad47**（config/winplat，新增 29，含新建 test_ripecheck.py 11 例、test_winmsg.py 5 例）、
**C=445a041**（纯文档 4 项）。核验动作与结果：

1. **全量测试**：**327 passed**（基线 288 → +39），连跑稳定。
2. **diff 逐片复核**：
   - A 片：P3-5 的 `from_override_start` 按事件逐次计算、无状态残留，OVERRIDE_START 首次文案与 override 期 CHECK_PASS 普通文案分流正确；P3-11 bool 兼容删除后三态路径完整（`str(RuleStatus).upper()` 成立）；P3-19 去重仅作用于 EXIT（队列锁内查重，其他命令不受影响）；P3-6 callable 签名兼容 pystray `(item)` 求值。
   - B 片：P3-3 选 count≤7 截断（(64−8)//8，口径可静态推导，单 record 实际 1-3 串，合理）；P3-4 分发保留 host 前缀 lower 后 endswith 判定正确；P3-9 标题判变真实触发 SetWindowTextW（已核源码非仅记账）；P3-1/P3-2 校验对称。
   - **无缺陷发现**（与 P2 核验不同，本轮无需修复项）。
3. **行为变更提示**：P3-12a 使 `--check` 在"探测未全部成功（unconfirmed）"时退出码也由 0 变非 0（fail-closed 方向：单轮快照未确认通过不给"一切正常"信号）——与 README"不可达不下已放行断言"口径一致。
4. **实机 smoke**：`scripts/run_guardian.py --check` 全链路通过——五项检查全过、检查⑤归属国判定与运行时一致（P2-1 修复实机生效）、退出码 0、只读不碰防火墙。
5. **红线**：各片提交前 grep 自查无输出；核验 diff 样本 IP 全部为 RFC 5737/文档段。

**结论：docs/04 第四节 P3 清单全部落地（剔除项见文首），核验通过。**
