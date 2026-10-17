# Claude Guard 架构设计文档

版本：1.0
日期：2026-10-15
依据：docs/01-requirements.md

---

## 1. 系统总览

```
┌─────────────────────────────────────────────────────┐
│                 claude-guard.exe                     │
│         (PyInstaller 单文件, 管理员权限)              │
│                                                      │
│  ┌──────────┐   事件队列    ┌──────────────┐         │
│  │ Tray     │◄─────────────││ Guardian     │         │
│  │ (pystray)│              ││ (主循环线程)  │         │
│  └────┬─────┘              └──────┬───────┘         │
│       │ 菜单命令队列               │ 调用             │
│       ▼                          ▼                  │
│  ┌──────────────────────────────────────────┐       │
│  │              core (纯逻辑)                │       │
│  │  StateMachine  Checks  Policy  Drift      │       │
│  └──────────────────┬───────────────────────┘       │
│                     │ 接口调用                        │
│  ┌──────────────────▼───────────────────────┐       │
│  │           platform (副作用薄层)           │       │
│  │  Firewall(PS)  NetProbe  DNS  Notify     │       │
│  └──────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────┘
        │                        │
        ▼                        ▼
  Windows WFP 防火墙            外部端点 (DoH/RIPE/echo)
  CG-Global (IPv4 门控)         1.1.1.1 / stat.ripe.net /
    160.79.104.0/23             www.cloudflare.com/cdn-cgi/trace
  CG-V6 (IPv6 永久封死, 常开)
    2607:6bc0::/48
    2607:6bc0:11::/48
  CG-FakeIP (门控, 与 CG-Global 同步)
    claude 域名当前解析到的 fake-ip (198.18.x.x)
```

核心决策：**core 层不产生任何副作用**（不碰网络、不碰防火墙、不碰 UI），所有副作用收敛到 platform 薄层与 Tray。这使状态机可以纯函数式单测——这是全项目联调风险的主要对冲。

## 2. 模块划分

### 2.1 `core/` — 纯逻辑域（无副作用，可单测）

| 模块 | 职责 | 关键接口 |
|---|---|---|
| `statemachine.py` | 门禁状态机。状态：`BLOCKED` / `ALLOWED`（二值）+ 正交标志 `drift_alarm` / `on_override`（`GateState` frozen dataclass） | `transition(state: GateState, event) -> (new_state: GateState, actions)` |
| `checks.py` | 四项环境检查的**判定逻辑**（结果的解释、比较、确认窗计数） | `evaluate(check_results, verdict, counter: CheckCounter) -> verdict`（counter 承载确认窗/不可达计数，跨 tick 持久） |
| `policy.py` | 白名单比对、探测失败 vs 不匹配的分流规则、override 过期判断 | `classify(probe_result, whitelist) -> CLEAN / DIRTY / UNREACHABLE` |
| `drift.py` | 漂移检测的判定逻辑（diff、与封禁段比对） | `detect_drift(dns_answers, ripe_prefixes, blocked_cidr) -> DriftReport` |
| `config.py` | 配置加载/校验（dataclass + json schema 校验） | `load(path) -> Config` |

**状态机定义**（按 `core/statemachine.py` 实际实现）：

```
状态：BLOCKED, ALLOWED（二值）+ 正交标志位：drift_alarm（漂移告警）、on_override（临时放行中）
事件：FAST_FAIL(本地快路径失败：mihomo 消失/TUN 消失),
      CHECK_PASS, CHECK_FAIL, PROBE_UNREACHABLE, OVERRIDE_START,
      OVERRIDE_EXPIRE, DRIFT_DETECTED
状态载体：GateState(state, drift_alarm, on_override)（frozen dataclass）

转换（核心）：
ALLOWED  --FAST_FAIL---------> BLOCKED   (action: firewall.enable, notify)  ← 无确认窗、无容忍
BLOCKED  --FAST_FAIL---------> BLOCKED   (幂等，不重复通知)
BLOCKED  --CHECK_PASS×N连续--> ALLOWED   (action: firewall.disable 放行, notify；on_override 保留)
ALLOWED  --CHECK_PASS--------> ALLOWED   (幂等)
ALLOWED  --CHECK_FAIL--------> BLOCKED   (action: firewall.enable, notify；DIRTY 出口立即阻断，G-4)
BLOCKED  --CHECK_FAIL--------> BLOCKED   (幂等)
ALLOWED/BLOCKED --PROBE_UNREACHABLE--> 保持原态（计数升级在 checks.py；升级后以 CHECK_FAIL 到达状态机）
任意     --OVERRIDE_START----> on_override=True + firewall.disable + notify（计时由 guardian 管，override_minutes）
on_override --FAST_FAIL/CHECK_FAIL/PROBE_UNREACHABLE--> 保持原态（检查不阻断，矩阵 #6）
on_override --OVERRIDE_EXPIRE--> BLOCKED (action: firewall.enable, notify；无论当前环境)
任意     --DRIFT_DETECTED----> drift_alarm=True（正交标志位，附着于任意状态，不参与放行决策，幂等）
未定义的 (state, event) 组合抛 ValueError（fail-closed：调用方捕获后回落阻断）
```

**快慢双路径（guardian 主循环内两个节拍，单线程调度）**：

```
快路径（fast_tick, 默认 1s，纯本地零网络）：
  psutil 检查 mihomo 进程 + TUN 网卡 → 任一消失 → FAST_FAIL 事件
  → ALLOWED 态下立即 Enable 规则（Clash 死亡 → FAST_FAIL 端到端阻断 ≤1.5s）

慢路径（slow_tick, 默认 5s，网络探测）：
  echo 出口 IP + fake-ip 生效 → CHECK_PASS / CHECK_FAIL / PROBE_UNREACHABLE
  → 按 G-1/G-4 三分法处理

实现：主循环按最小周期 1s 轮转，fast 每轮必查（psutil 开销 <1ms），
slow 每 5 轮查一次。单线程无竞态。
可选增强（M2 可选，约半天）：WMI 进程退出事件订阅 → Clash 死亡延迟 <100ms。
```

### 2.2 `platform/` — 副作用薄层（每项可独立 mock）

| 模块 | 职责 | 实现 |
|---|---|---|
| `firewall.py` | **三条规则**：CG-Global（IPv4 门控，Enable/Disable 随状态机）+ CG-V6（IPv6 永久 Enabled，启动时 ensure_exists，此后每轮只校验不切换——门禁无权放行）+ CG-FakeIP（门控，与 CG-Global 同步 Enable/Disable；RemoteAddress = claude_domains 当前解析到的 fake-ip 集合，慢路径每轮重采集、变化即重建）；规则存在性校验、创建、状态读取 | `powershell -NoProfile -Command "..."` 子进程封装 NetSecurity cmdlet；**同步切换路径（set_blocking/block_all）先走 netsh 快车道**（~235ms/次，规避 PS ~2.5s/进程加载税），CG-Global 操作失败才回退 PS 全量（缺失重建+复查+权限分类）。规则状态校验由独立 heal 线程承担 |
| `netprobe.py` | echo 探测（主备双端点）、mihomo 进程检测、TUN 网卡检测 | `requests`(echo)、`psutil`(进程/网卡) |
| `dnscheck.py` | fake-ip 生效检测、DoH 解析 | fake-ip：`socket.getaddrinfo` 检查返回 198.18.x.x；DoH：`https://1.1.1.1/dns-query?name=X&type=A`（json） |
| `ripecheck.py` | RIPE announced-prefixes 查询 | `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS399358` |
| `notify.py` | Toast、托盘气泡、图标切换指令 | `win11toast`（Toast）；托盘气泡走 pystray |

### 2.3 `tray.py` — 表示层

- pystray `Icon`，独立线程运行消息循环
- **线程通信**：`queue.EventQueue`（core→tray：状态变化事件）；`queue.CommandQueue`（tray→guardian：菜单命令）。禁止跨线程直接调用。
- 图标：三个预渲染 PNG（green/red/yellow），项目资源内嵌
- 菜单动作全部只投递命令，由主循环统一执行——托盘线程永不阻塞

### 2.4 `guardian.py` — 主循环（组装层）

```python
while True:  # fast_tick 周期（默认 1s）
    if fast_tick():                              # ① 快路径：psutil 本地检查（<1ms）
        verdict = FAST_FAIL                      #    mihomo/TUN 消失 → 立即事件
    elif slow_due():                             # ② 慢路径：每 N 个 fast 周期执行一次
        results = collect_checks(platform)       #    echo + fake-ip（网络探测）
        verdict  = core.checks.evaluate(results, verdict_ctx, counter) #    判定（纯；counter 跨 tick 持久）
    actions  = core.statemachine.transition(state, verdict)  # ③ 转移（纯）
    execute(platform, actions)                   # ④ 执行副作用（CG-Global/CG-FakeIP 门控切换；CG-V6 只校验）
    tray.push(state_summary)                     # ⑤ 通知 UI
    if pending_commands: handle(command)         # ⑥ 处理菜单命令
```

单线程顺序执行，无并发副作用问题；漂移监控（1h/24h 定时）为独立守护线程，只产生事件入队，不做任何动作。

### 2.5 `config.json` — 全部可变量

实际字段以 `config.example.json` 与 `core/config.py` 的 `Config` dataclass 为准，示例：

```json
{
  "blocked_cidrs_v4": ["160.79.104.0/23"],
  "blocked_cidrs_v6": ["2607:6bc0::/48", "2607:6bc0:11::/48"],
  "rule_name_v4": "CG-Global",
  "rule_name_v6": "CG-V6",
  "rule_name_fakeip": "CG-FakeIP",
  "whitelist": ["203.0.113.10"],
  "dns_whitelist": [],
  "dns_egress_countries": ["US"],
  "dns_probe_domain": "whoami.ds.akahelp.net",
  "echo_endpoints": [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ip.sb/ip"
  ],
  "fakeip_range": "198.18.0.0/15",
  "mihomo_process": "verge-mihomo.exe",
  "tun_adapter_keywords": ["mihomo", "clash", "utun", "verge"],
  "fast_tick_sec": 1,
  "slow_tick_sec": 5,
  "pass_confirm_count": 3,
  "fail_unreachable_threshold": 5,
  "doh_check_interval_min": 60,
  "ripe_check_interval_hours": 24,
  "override_minutes": 30,
  "claude_domains": ["claude.ai", "api.anthropic.com", "anthropic.com", "console.anthropic.com"],
  "asn": "AS399358",
  "log_dir": "logs",
  "log_retention_days": 30
}
```

## 3. 关键交互序列

### 3.1 正常放行

```
Guardian          Firewall         Tray            User
   │ probe echo ──► CF trace 返回 IP
   │ IP∈白名单 ×3 连续
   │ transition BLOCKED→ALLOWED
   │────Disable────►│
   │─────────────────────状态事件──────────►│ 图标绿+Toast
```

### 3.2 阻断态死锁规避（本架构最关键设计）

```
阻断态下 Guardian 不探测 claude.ai（会被自己的 WFP 规则拦死）
  而是探测 echo 端点：
  - echo 与 claude.ai 在 mihomo 中同代理组（用户配置保证，见 §5）
  - echo 不在封禁段 → 阻断态下探测照常工作
  - echo 返回 IP = 该代理组出口 = claude.ai 的出口（等价代表）
```

### 3.3 Clash 关闭（核心事故场景）

```
mihomo 进程消失 → 快路径（≤1s 后的下个 fast_tick，psutil <1ms）→ FAST_FAIL
→ ALLOWED→BLOCKED（无确认窗、无容忍）→ Enable CG-Global → 红灯+Toast
→ 总延迟 ≤1.5s（FAST_FAIL 端到端；阻断动作 netsh 快车道 ~0.4s）
若用户未开 Clash 而 msedge/omp/node 连 claude.ai：
→ WFP 直接拒绝 connect()，零流量出站
注：Clash 死亡本身拔掉 TUN，存量连接随 TUN 中断；WFP 拦截新连接。
（M1 冒烟时实测存量连接行为并记录。）

### 3.4 漂移告警（正交，不阻断）

```
Drift 线程: DoH 解析 claude.ai = 203.0.113.5 (不在 160.79.104.0/23)
→ DRIFT_DETECTED 事件 → Tray 黄灯叠加 + Toast
→ 规则不动，等待用户改 config 中的 blocked_cidrs
```

## 4. 线程模型

| 线程 | 数量 | 阻塞点 | 通信 |
|---|---|---|---|
| Guardian 主循环（guardian-main） | 1 | sleep(fast_tick) | 出：EventQueue；入：CommandQueue |
| Tray (pystray) | 1 | 系统消息循环 | 入：EventQueue；出：CommandQueue |
| Drift 监控 | 1 | sleep(长周期) | 出：EventQueue（仅事件） |
| rule-heal（规则自愈） | 1 | Event.wait(30s)（可被 `_heal_wake` 提前唤醒） | 共享防火墙状态，受 `_fw_lock` 与主循环互斥 |
| fakeip-refresh（CG-FakeIP 重采集/重建） | 1 | Event.wait(5s)（可被 `_fakeip_wake` 提前唤醒） | 同上，受 `_fw_lock` 互斥 |
| Python 主线程 | 1 | join | 启动/清理 |

线程通信以 `queue.Queue` + `threading.Event` 为主；防火墙操作（规则启停/重建/heal）
通过 `threading.Lock`（`_fw_lock`）按次互斥——主循环与 heal/fakeip-refresh 线程
不并发改规则，但共享状态存在，并非"无锁"。

## 5. 外部依赖与前提（用户侧一次性配置）

1. **mihomo 分流对齐**（唯一用户配置前提）：确保 `cloudflare.com`（或所选 echo 端点域名）与 `claude.ai` 走同一代理组。**已知未缓解风险**：echo 出口白名单命中 ≠ Claude 实际出口——程序无法自动校验"探测路径 = Claude 路径"这一前提（echo 的出口属于 echo 自己的分流组），依赖用户保持分流对齐；若用户改坏分流，门禁会"放行但 Claude 走了别的出口"。

## 6. 数据与日志

- `logs/guard-YYYYMMDD.log`：状态转移、检查结果摘要、override、漂移、错误（按天滚动，保留 30 天）
- `logs/override-audit.log`：override 时间、时长（原因选项不做，T-5 需求已降级）
- 无任何遥测上报（隐私工具自身不产生隐私问题）

## 7. 技术栈锁定

| 组件 | 选型 | 版本锁定 |
|---|---|---|
| 语言 | Python | 3.13 |
| 托盘 | pystray | 0.19 |
| 图像 | Pillow | 11.x |
| HTTP | requests | 2.32+ |
| 进程/网卡 | psutil | 7.x |
| Toast | win11toast | 0.35 |
| 打包 | PyInstaller | 6.x（`--uac-admin`） |

## 8. 已知残余风险（验收时接受）

| 风险 | 量级 | 缓解 |
|---|---|---|
| 轮询窗口内脏请求 | ≤ 探测周期(5s) + RTT | 不可消除，窗口已最小化 |
| IP 段漂移发现延迟 | ≤1h（DoH 周期） | 漂移告警 + 人工更新 |
| geo-DNS 分区解析 | 理论 | 当前 Anthropic 单 IP 事实 + RIPE 交叉验证 |
| 探测路径分流被用户改坏 | 持续（无自动校验） | **已知未缓解风险**：echo 出口白名单命中 ≠ Claude 实际出口，依赖用户保持分流对齐（见 §5） |
| WFP 规则被第三方安全软件重置 | ≤30s（自愈周期） | 自愈每 30s 校验 + 状态迁移后必查 + 失败下一轮立即重试 |
| B-7 时序残余：含自愈 PS 调用的 tick | 最坏 ~4–5s（29/30 tick 满足 ≤1.5s） | 自愈移出快路径 + FAST_FAIL 当轮跳过；如需绝对时延上限改 WFP API 直调 |
| 规则切换延迟 | netsh 快车道实测 ~0.4s/次（FAST_FAIL 端到端 ≤1.5s）；PS 回退路径实测 2.7–3.8s/次 | netsh 覆盖 enable/disable 热路径；如需毫秒级改 WFP API/Go 服务 |
| override 窗口内强杀进程 | 最长 30min 放行态裸奔 | 审计日志 + 用户自担；看门狗任务为可选后续 |
| 放行态强杀/quit | 退出路径无组件恢复 Enabled | 靠计划任务 RestartCount=3 自动拉起与下次启动 preheat（P2-7 后启动即阻断）兜底；阻断态下无此问题（fail-closed） |
| CG-V6 被第三方禁用的暴露窗口 | ~30s | 暂停期间每 tick 校验；正常态每 30s ensure_enabled_v6 |
| 旧版 TCP-only 规则升级不自动迁移 | 升级部署 | 首次部署无存量；升级时手动删两条 CG-* 规则或改 config 触发重建（发布说明已记） |
