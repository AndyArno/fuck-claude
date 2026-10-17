# 06 — P2 级问题修复方案（2026-10-17）

配套：`docs/04-audit-2026-10.md`（发现清单）。本文档给每项 P2 的根因、改动点、验收标准与执行分片。
前置状态：P1 已全部修复（157e3b6 + 697c9d1），netsh 快车道已落地（a2ecbc6），基线 247 passed。

分片原则：按文件归属避免并行冲突。A=guardian.py 及其测试；B=winplat/core/scripts 及其测试；
C=纯文档。P2-3 跨 A/B，接口契约见该项。

---

## A 片（guardian.py + tests/test_guardian.py）

### P2-1 selfcheck 漏传 `dns_egress_countries`
- **根因**：`aae5285` 给运行时 `_probe_dns_egress` 加了第三参，selfcheck（`guardian.py` 两参调用处）漏改。
- **改动**：selfcheck 调用补 `list(config.dns_egress_countries)`；`tests/test_guardian.py` 中两参桩签名同步（`lambda domain, wl, countries=None: ...`）。
- **验收**：新增用例——monkeypatch `dnscheck.check_dns_egress` 记录实参，断言 selfcheck 传出 config 的国家列表。

### P2-3（guardian 侧）`dns_whitelist` 消费点去掉 `or` 回退
- **接口契约（与 B 片共同遵守）**：`config.load()` 语义改为——`dns_whitelist` 键**存在**（含显式 `[]`）→ 用之；键**缺失** → 回退 `whitelist`。load 已补齐回退，**消费方一律直接用 `cfg.dns_whitelist`，不得再 `or`**。
- **改动**：`guardian.py` 两处 `self.config.dns_whitelist or self.config.whitelist` → `self.config.dns_whitelist`。
- **验收**：现有测试全绿；B 片 config 测试覆盖 [] 语义，A 片不重复。

### P2-5 tick 内残留 PS 直调（B-7）
- **范围**：只处理三类**非权威** PS 调用；状态机迁移动作（`set_blocking`，权威写入）不在本项（netsh 快车道已压到 ~0.4s）。
- **改动**：
  1. **暂停分支 per-tick `ensure_enabled_v6` 删除**：heal 线程每 30s 已无条件 ensure CG-V6（暂停时照常跑，`expected_enabled` 暂停语义只影响门控两规则）。删除后暂停态 tick 零 PS。
  2. **慢路径 `_refresh_fakeip_rule` 的 `create_rule_fakeip` 重建**：慢路径只重采集集合并 `self._fakeip_wake.set()`，重建动作收敛到 `_fakeip_refresh_loop` 线程执行（该线程已有此职责与 `_fw_lock` 互斥）。注意保留"集合无变化不重建"逻辑，避免每 5s 白唤醒。
  3. **热重载 `_rebuild_blocked_rules` 的 create_rule/create_rule_v6/ensure_enabled_v6**：移出 tick。热重载在 tick 内只做 config 换指针 + 置标志位/唤醒 heal 线程，由 heal 线程检测"配置代际变化"后执行重建。设计自行决定（如 `self._pending_rebuild` 标志 + heal 轮首检查），但**必须保持**：重建后 v6 强制 Enabled、失败不破坏旧规则语义（fail-closed）。
- **验收**：新增用例——构造暂停态/慢路径 fakeip 变化/热重载三场景，FakeFirewall 记录调用线程名，断言 tick（guardian-main）内无 `create_rule*`/`ensure_enabled_v6` 调用；重建最终仍发生（heal/fakeip 线程）。现有测试全绿。

### P2-7 启动预热不确保 CG-Global Enabled
- **根因**：`_preheat` 只 `ensure_exists`（不 enable），上次放行态强杀残留 Disabled 时存在 ~5-13s 未阻断窗口。
- **改动**：preheat 首步 `ensure_exists` 后追加 `set_blocking(True)`（或改调 `block_all` 思路，但注意 preheat 时 fakeip 集合尚未采集——用 `set_blocking(True)` 即可，netsh 快车道实测 ~0.4s 不拖启动）。启动期 `_stop` 未置位，与 P1-2 无冲突。
- **验收**：用例——FakeFirewall 初始 `global_enabled=False`，`start()`（或 `_preheat()`）后断言 `global_enabled is True`；确保 pause/ALLOWED 初始态不影响（启动初态恒 BLOCKED）。

### P2-8 日志保留期清理失效（extMatch）
- **根因**：自定义 `suffix="%Y%m%d"` + namer 产物 `guard-20261016.log`，`TimedRotatingFileHandler.extMatch` 仍是默认 `^\d{4}-\d{2}-\d{2}`，匹配永不命中（已实测复现），`getFilesToDelete` 恒空。
- **改动**：`setup_logging` 中加 `handler.extMatch = re.compile(r"^\d{8}(\.\w+)?$")`。
- **验收**：用例——tmp_path 下造 `guard-20261001.log`（旧）与 `guard-20990101.log`（新），实例化 handler 后调 `getFilesToDelete()`，断言旧文件在删除列表、新文件不在。

### P2-14（A 侧）TestSelfcheck 不密闭
- **根因**：`TestSelfcheck` 只打桩 5 项，`selfcheck` 内的 `collect_fakeips`（真实 getaddrinfo）与 `get_status_fakeip`（真实 PS）未打桩，CI 依赖本机环境。
- **改动**：补齐打桩（fakeip 采集返回固定集合、防火墙状态读返回固定三态）。
- **验收**：用例在断网/无同名规则机器语义下也可运行（全 mock 后无真实子进程——可用 monkeypatch `subprocess.run` 抛错断言零调用）。

---

## B 片（winplat/dnscheck.py、core/config.py、core/messages.py、winplat/firewall.py、scripts/、一键切换防火墙状态.cmd + 对应测试）

### P2-2 geo 查询失败负缓存 1h
- **根因**：`lookup_country` 把 `country=None` 与成功结果同 TTL（1h）写缓存，瞬时故障被放大为最长 1h 的 UNREACHABLE→确认窗升级阻断。
- **改动**：失败结果单独短 TTL（建议 60s，常量 `_GEO_FAIL_TTL`）；成功仍 1h。顺手清理：写入时顺带剔除过期项（`_geo_cache` 只增不减，P3 卫生项一并做）。
- **验收**：用例——monkeypatch 网络层先抛错后成功，断言失败后 60s 内重查会真正再发请求（不被缓存压制）、成功后按 1h 缓存。

### P2-3（config 侧）`dns_whitelist: []` 被 `or` 链吞掉
- **改动**：`core/config.py` load 按 A 片接口契约改存在性判断：
  `list(data["dns_whitelist"]) if "dns_whitelist" in data else list(data.get("whitelist", []))`。
  同步更新该处注释（None/[] 语义约定与 drift 一致）。
- **验收**：`tests/test_config.py` 用例——显式 `[]` → `cfg.dns_whitelist == []`（不回退）；键缺失 → 回退 whitelist；显式值 → 用之。

### P2-4 reason_text 残留"环境正常"矛盾文案
- **根因**：`dns_egress_ok=False` 且 `dns_leak_ip=None`（akahelp 有应答无可解析 IP）时各分支全跳过，落兜底"代理环境正常"。
- **改动**：`core/messages.py` `reason_text` 在 `dns_leak_ip` 分支后补：
  `if s.dns_egress_ok is False: return "DNS 解析出口异常（探针应答无法确认出口，已按泄漏处理）"`。
- **验收**：用例构造该 Status，断言 reason_text/toast_block 不含"环境正常"。

### P2-6 smoke_fw 用 `-Protocol TCP` 建生产同名规则
- **根因**：`scripts/smoke_fw.py` 建规则带 `-Protocol TCP`；中断残留 TCP-only 同名规则 → heal 只查 Enabled 不重建 → UDP/QUIC 长期放行。
- **改动**：去掉两处 `-Protocol TCP`；`ps()` 补 `CREATE_NO_WINDOW`（对齐硬约束⑥）。
- **验收**：grep 断言脚本无 `-Protocol`；实机 smoke（由主审查线最后统一跑，B 片不必跑）。

### P2-9 block_all PS 回退路径：CG-FakeIP 存在但 Disabled 时校验抛错无修复
- **背景**：netsh 快车道已覆盖常见路径（CG-FakeIP 存在即被 netsh enable）；本项修 **PS 回退路径**的同一语义。
- **改动**：`winplat/firewall.py` `block_all` 的 PS 脚本——`fakeip_part` 拆两段：CG-FakeIP **存在即 Enable**（无条件，`-ErrorAction Stop`），**缺失且 fakeip_ips 非空才重建**。即 fakeip_ips 为空时仍对已存在的 CG-FakeIP 执行 Enable。
- **验收**：离线用例——fakeip_ips=None 时断言脚本仍含对 n2 的 Enable；fakeip_ips 非空时含 New-NetFirewallRule 重建段。

### P2-10 一键切换脚本可整体停用 CG-V6 无警示
- **改动**：`一键切换防火墙状态.cmd`——选项 2（停用）把 CG-V6 从批量停用中排除（或停用前二次确认并明示"将失去 IPv6 防线"）；README 对应段补警示。
- **验收**：脚本内 CG-V6 不再出现在 Disable 路径（或出现在带显式确认的分支）；README 文字同步。

### P2-14（B 侧）测试缺口：ECS 判定、fakeip 边界、_run_ps 双解码
- **改动**：
  1. `tests/test_dnscheck.py` 补 `parse_ecs_cidr` 与 check⑤ ECS 三条判定用例（ECS∈白名单放行、/24 supernet、/16 归属——喂样本文本，不发网络；样本一律 RFC 5737/RFC1918/文档段）；
  2. `check_fakeip` 边界：坏网段 ValueError、OSError、空集、网段首/尾地址含属与相邻段不含属；
  3. `tests/test_firewall.py` 补 `_run_ps` rc≠0 分类（权限 marker 各形态含"拒绝访问"、普通错误）与 `_dec` UTF-8→mbcs 回退（monkeypatch subprocess.run 返回 bytes）。
- **验收**：新增用例有行为断言（非 not-throw）；全套绿。

---

## C 片（纯文档：docs/01、02、03、README.md）

### P2-11 §5"分流对齐自动校验"声称未实现
- **决策**：不实现（功能开发超出本次范围），文档降级——docs/02 §5 与 §8 对应行改写为"已知未缓解风险：echo 出口白名单命中 ≠ Claude 实际出口；依赖用户保持分流对齐"。

### P2-12 时序验收数据矛盾
- **改动**：docs/01 B-4/B-7 与 docs/02 §8 按实测回写——netsh 快车道路径：阻断动作 ~0.4s（FAST_FAIL 端到端 ~1.5s 内）；PS 回退路径 2.7-3.8s。验收场景 2 的秒表口径同步。

### P2-13 docs/02 模块契约/状态机/线程模型过时
- **改动**：删 `PROBING`/`USER_PAUSE/USER_RESUME` 不存在项；状态机表按 `core/statemachine.py` 实际（BLOCKED/ALLOWED + 正交标志）；线程表补 rule-heal、fakeip-refresh；删"无锁"表述（有 `_fw_lock`，按次互斥）；§2.5 配置示例与 `config.example.json` 对齐（或改为引用）；§2.4 伪代码 `evaluate(results)` 补 `counter` 参数；`win11toast==0.35`（对齐 requirements.txt）。

### P2-15 docs/03 口径
- **改动**：矩阵 #9 语义回写为"立即 BLOCK_NOW"（与 tests/test_statemachine.py 一致）；"8 项/9 项"计数统一为 9 条验收场景、12 条矩阵用例。

### P2-16 B-5 绝对化与 quit 语义
- **改动**：docs/01 B-5 补限定"阻断态下"；docs/02 §8 残余风险表补一行"放行态强杀/quit：无组件恢复 Enabled，靠计划任务 RestartCount=3 与下次启动 preheat（P2-7 后启动即阻断）兜底"。

### P2-17 T-5"原因选项"未实现
- **决策**：需求降级——docs/01 T-5 改写为"临时放行只记时间/时长审计，原因选项不做"（或移入"可选后续"）。README 若提及同步。

### 附带（C 片顺手）
- AGENTS.md"当前 169 passed"计数改为实施时实测数；docs/03 5.5"冒烟脚本清理完毕"与现状矛盾的表述修正；README 配置表补 `dns_probe_domain`/`dns_whitelist`/`rule_name_fakeip`、黄灯语义补 override。

---

## 执行与核验

1. 三片并行实施（各自文件集不相交）；各自跑全量 pytest 后**分片提交**（中文 commit，格式遵 AGENTS.md）。
2. 主审查线最后统一核验：全套 pytest、逐片 diff 复核 fail-closed 语义、实机 smoke（P2-6/P2-7/P2-9 涉及 firewall/smoke）。
3. **红线**：任何代码/测试/文档/提交不得出现真实出口 IP/网段/DNS 出口——一律 RFC 5737 保留地址或代称；提交前 `git diff --cached | grep -E "63\.125|183\.232|23\.132|172\.253|103\.142|74\.125"` 自查。

---

## 核验记录（2026-10-17，主审查线）

三片均已实施并提交：**A=1f8be88**（287 中 A 新增 7）、**B=924d938**（新增 21）、**C=8106557**（纯文档）。核验动作与结果：

1. **全量测试**：288 passed（基线 247 → 三片 +40 → 核验补 1），连跑稳定。
2. **diff 逐片复核**（fail-closed 焦点）：
   - A 片：fakeip 重建收敛 refresh 线程（pending 无变化不白唤醒）、热重载 `_pending_rebuild` 由 heal 代际消费、preheat `set_blocking(True)` 封死启动窗、selfcheck 第三参——语义保持，通过。
   - B 片：geo 失败 60s 短 TTL + 过期清理、config 存在性语义、reason_text 新分支（echo 脏优先级保持）、smoke 去 -Protocol、block_all CG-FakeIP 恒 Enable——方向正确，**但抓到一个实现缺陷**，见 4。
3. **P2-8 extMatch 偏离独立复验**：代理实测否决了方案给的模式（`^\d{8}(\.\w+)?$` 在 namer 路径下 `extMatch.search` 永不命中），改用 `\d{8}(?=\.log$)` 前瞻——主审查线独立构造 backupCount=1 + 双文件实测：旧文件入删除列表、新文件保留。**偏离成立，为正确修正**（方案文档此处作废，以代码注释为准）。
4. **核验抓到并修复的缺陷（2e58167）**：P2-9 的 Enable n2 恒在但未带存在性守卫——`Enable-NetFirewallRule` 对缺失名带 `-ErrorAction Stop` 是**终止错误**（本机实测 rc=1、后续语句不执行），"CG-FakeIP 缺失 + fakeip_ips 为空"时回退脚本整段被打死：CG-Global 已启用但复查段执行不到、block_all 误报失败、退出路径 `_fw_tolerant` 白重试 3 次。已修为"先 Get 存在再 Enable"，补回归用例 `test_enable_n2_is_existence_guarded`。
5. **实机验证**（管理员）：强制禁用 netsh 走 PS 回退——①CG-FakeIP 存在 Disabled → `block_all(cfg, None)` 后两规则全 Enabled；②删除 CG-FakeIP + ips=None → 不再报错、CG-Global ENABLED（修复前必死脚本）。`smoke_fw.py`（P2-6 后版本）全过：阻断/放行/存量连接行为符合预期。机器规则状态已还原为测试前（CG-Global/CG-FakeIP Disabled、CG-V6 Enabled）。
6. **红线**：各片提交前 grep 自查无输出；核验 diff 中样本 IP 全部为 RFC 5737/文档段。

**结论：17 项 P2 全部落地，核验通过。** 残余已知项：P2-11（分流对齐校验）按决策只做文档降级未实现；P2-17（T-5 原因选项）按决策需求降级。
