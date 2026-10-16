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
```

核心决策：**core 层不产生任何副作用**（不碰网络、不碰防火墙、不碰 UI），所有副作用收敛到 platform 薄层与 Tray。这使状态机可以纯函数式单测——这是全项目联调风险的主要对冲。

## 2. 模块划分

### 2.1 `core/` — 纯逻辑域（无副作用，可单测）

| 模块 | 职责 | 关键接口 |
|---|---|---|
| `statemachine.py` | 门禁状态机。状态：`BLOCKED` / `PROBING` / `ALLOWED` / `DRIFT_ALARM`（正交） | `transition(state, event) -> (new_state, actions)` |
| `checks.py` | 四项环境检查的**判定逻辑**（结果的解释、比较、确认窗计数） | `evaluate(check_results, config, counter) -> verdict` |
| `policy.py` | 白名单比对、探测失败 vs 不匹配的分流规则、override 过期判断 | `classify(probe_result, whitelist) -> CLEAN / DIRTY / UNREACHABLE` |
| `drift.py` | 漂移检测的判定逻辑（diff、与封禁段比对） | `detect_drift(dns_answers, ripe_prefixes, blocked_cidr) -> DriftReport` |
| `config.py` | 配置加载/校验（dataclass + json schema 校验） | `load(path) -> Config` |

**状态机定义**：

```
状态：BLOCKED, PROBING, ALLOWED
事件：FAST_FAIL(本地快路径失败：mihomo 消失/TUN 消失),
      CHECK_PASS, CHECK_FAIL, PROBE_UNREACHABLE, OVERRIDE_START,
      OVERRIDE_EXPIRE, USER_PAUSE, USER_RESUME, DRIFT_DETECTED

转换（核心）：
ALLOWED  --FAST_FAIL---------> BLOCKED   (action: firewall.enable, notify)  ← 无确认窗、无容忍
BLOCKED  --CHECK_PASS×N连续--> ALLOWED   (action: firewall.enable 放行, notify)
ALLOWED  --CHECK_FAIL--------> BLOCKED   (action: firewall.enable, notify)
ALLOWED  --PROBE_UNREACHABLE--> ALLOWED  (仅计数，连续 M 次后 → BLOCKED + 告警)
任意     --OVERRIDE_START----> 允许放行30min（计时器，不受检查影响）
DRIFT_ALARM 为正交标志位，附着于上述任意状态，不参与放行决策
```

**快慢双路径（guardian 主循环内两个节拍，单线程调度）**：

```
快路径（fast_tick, 默认 1s，纯本地零网络）：
  psutil 检查 mihomo 进程 + TUN 网卡 → 任一消失 → FAST_FAIL 事件
  → ALLOWED 态下立即 Enable 规则（Clash 死亡 → 阻断 ≤2s）

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
| `firewall.py` | **两条规则**：CG-Global（IPv4 门控，Enable/Disable 随状态机）+ CG-V6（IPv6 永久 Enabled，启动时 ensure_exists，此后每轮只校验不切换——门禁无权放行）；规则存在性校验、创建、状态读取 | `powershell -NoProfile -Command "..."` 子进程封装 NetSecurity cmdlet。**每次主循环校验规则实际状态**（防第三方安全软件重置） |
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
        verdict  = core.checks.evaluate(results) #    判定（纯）
    actions  = core.statemachine.transition(state, verdict)  # ③ 转移（纯）
    execute(platform, actions)                   # ④ 执行副作用（仅 CG-Global 切换；CG-V6 只校验）
    tray.push(state_summary)                     # ⑤ 通知 UI
    if pending_commands: handle(command)         # ⑥ 处理菜单命令
```

单线程顺序执行，无并发副作用问题；漂移监控（1h/24h 定时）为独立守护线程，只产生事件入队，不做任何动作。

### 2.5 `config.json` — 全部可变量

```json
{
  "blocked_cidrs_v4": ["160.79.104.0/23"],
  "blocked_cidrs_v6": ["2607:6bc0::/48", "2607:6bc0:11::/48"],
  "rule_name_v4": "CG-Global",
  "rule_name_v6": "CG-V6",
  "whitelist": ["203.0.113.10"],
  "echo_endpoints": [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ip.sb/ip"
  ],
  "fakeip_range": "198.18.0.0/15",
  "mihomo_process": "verge-mihomo.exe",
  "fast_tick_sec": 1,
  "slow_tick_sec": 5,
  "pass_confirm_count": 3,
  "fail_unreachable_threshold": 5,
  "doh_check_interval_min": 60,
  "ripe_check_interval_hours": 24,
  "override_minutes": 30,
  "claude_domains": ["claude.ai", "api.anthropic.com", "anthropic.com", "console.anthropic.com"],
  "asn": "AS399358"
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
→ 总延迟 ≤2s
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
| Guardian 主循环 | 1 | sleep(interval) | 出：EventQueue；入：CommandQueue |
| Tray (pystray) | 1 | 系统消息循环 | 入：EventQueue；出：CommandQueue |
| Drift 监控 | 1 | sleep(长周期) | 出：EventQueue（仅事件） |
| Python 主线程 | 1 | join | 启动/清理 |

全部线程通过 `queue.Queue` 通信，无锁、无共享可变状态。

## 5. 外部依赖与前提（用户侧一次性配置）

1. **mihomo 分流对齐**（唯一用户配置前提）：确保 `cloudflare.com` 与 `claude.ai` 走同一代理组（规则 `- DOMAIN-SUFFIX,cloudflare.com,PROXY`）。工具启动时自动做一次双端点一致性校验（探测 claude.ai 与 echo 的 IP 是否一致），不一致则黄灯提示"分流未对齐"。
   - 注：放行态下 claude.ai 可达，此校验在放行态进行；阻断态退化为仅提示。

## 6. 数据与日志

- `logs/guard-YYYYMMDD.log`：状态转移、检查结果摘要、override、漂移、错误（按天滚动，保留 30 天）
- `logs/override-audit.log`：override 时间、时长、用户选择的原因
- 无任何遥测上报（隐私工具自身不产生隐私问题）

## 7. 技术栈锁定

| 组件 | 选型 | 版本锁定 |
|---|---|---|
| 语言 | Python | 3.13 |
| 托盘 | pystray | 0.19 |
| 图像 | Pillow | 11.x |
| HTTP | requests | 2.32+ |
| 进程/网卡 | psutil | 7.x |
| Toast | win11toast | 1.1+ |
| 打包 | PyInstaller | 6.x（`--uac-admin`） |

## 8. 已知残余风险（验收时接受）

| 风险 | 量级 | 缓解 |
|---|---|---|
| 轮询窗口内脏请求 | ≤ 探测周期(5s) + RTT | 不可消除，窗口已最小化 |
| IP 段漂移发现延迟 | ≤1h（DoH 周期） | 漂移告警 + 人工更新 |
| geo-DNS 分区解析 | 理论 | 当前 Anthropic 单 IP 事实 + RIPE 交叉验证 |
| 探测路径分流被用户改坏 | 用户操作 | 启动/放行态自动校验 + 黄灯提示 |
| WFP 规则被第三方安全软件重置 | 环境相关 | 主循环每轮校验规则状态，漂移即重建 |
