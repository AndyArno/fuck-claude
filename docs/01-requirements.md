# Claude Guard 需求文档

版本：1.0（定稿）
日期：2026-10-15
状态：经完整调研与实测验证，作为唯一施工依据

---

## 1. 项目背景

用户通过固定 ISP 出口 IP 访问 Claude（Edge 网页版 / omp 接入 Claude Pro/Max / Claude Code）。当代理环境异常（Clash 被关闭、DNS 覆写失效、出口 IP 变化）时，Claude 流量可能以真实 IP 直连 Anthropic 服务器，造成身份暴露与账号风控风险。

典型事故场景：用户打游戏时关闭 Clash 或改为直连，忘记恢复即启动 Claude，真实 IP 泄漏。

## 2. 核心思路（一句话）

**默认阻断本机到 Anthropic IP 段的所有出站流量，只有当代理环境被验证为"干净"时才放行**（Deny-by-default 门禁）。

## 3. 需求清单

### 3.1 阻断需求（核心）

| 编号 | 需求 | 验证标准 |
|---|---|---|
| B-1 | 默认阻断本机所有进程到 Anthropic IPv4 段（160.79.104.0/23）的出站连接（门控规则 CG-Global，随门禁切换）；配套门控规则 **CG-FakeIP** 阻断 claude 域名当前解析到的 fake-ip（198.18.x.x）地址，掐断"浏览器 → fake-ip → TUN → mihomo → 代理"这条绕过 CG-Global 的泄漏路径——DNS 泄漏（ECS 带真实网段）恰恰发生在使用过程中，必须让连接根本到不了 mihomo | 规则 Enabled 时，Edge 打不开 claude.ai、omp 无法调用 Claude API、Claude Code 无法连接 |
| B-2 | 阻断不依赖代理进程存活（内核级 WFP 规则） | 杀掉 verge-mihomo.exe 后阻断仍然有效 |
| B-3 | 阻断不影响其他任何流量 | 阻断态下 YouTube、GitHub、游戏、其他模型商 API 全部正常 |
| B-4 | 规则状态切换（Enable/Disable）。实测：netsh 快车道 ~0.4s/次；PowerShell cmdlet 回退路径 2.7–3.8s/次（原"<100ms"基于 WFP API 直调，当前实现不可达，见架构 §8） | 切换在 4s 内完成（快车道 ~0.4s；回退路径实测 2.7–3.8s）；切换期间规则不会处于"半开"状态（cmdlet 原子生效） |
| B-5 | **阻断态下**工具崩溃/被杀时，规则停留在阻断态（fail-closed）。放行态（含 override 窗口）强杀/退出无组件恢复 Enabled，残余风险见架构 §8 | 阻断态下强杀工具进程，Claude 仍不可达 |
| B-6 | **Anthropic IPv6 段（2607:6bc0::/48、2607:6bc0:11::/48）永久封死**：独立规则 CG-V6，常驻 Enabled，门禁永远无权放行。理由：代理走 IPv4，任何到 Claude 的 v6 连接必然是绕过代理的直连（防系统 IPv6 被误重新启用后 AAAA 直连） | 规则 CG-V6 存在且 Enabled；门禁任何状态下 IPv6 直连 claude.ai 均不可达 |
| B-7 | Clash 内核关闭必须**立即**阻断（快路径，纯本地进程/网卡检查，1s 周期，不等待网络探测） | Clash 死亡后 FAST_FAIL 端到端 ≤1.5s 内 Claude 不可达（阻断动作 netsh 快车道实测 ~0.4s；29/30 的快路径 tick 满足；含自愈 PS 调用的 tick 最坏 ~4–5s，见架构 §8 残余） |

### 3.2 放行需求（门禁）

| 编号 | 需求 | 验证标准 |
|---|---|---|
| G-1 | 慢路径检查全部连续通过 N 次后才放行：① mihomo 进程存活且 TUN 网卡存在 ② fake-ip 生效（DNS 解析返回 198.18.x.x）③ echo 探测出口 IP ∈ 白名单 | Clash 关闭 → 不放行；Clash 开启但出口脏 → 不放行 |
| G-2 | 出口 IP 白名单由用户手动维护（配置文件） | 编辑白名单后无需重启即可生效 |
| G-3 | 放行确认窗（连续 N 次通过）防 Clash 启动中间态闪断 | Clash 启动后至少 N×探测周期 才放行 |
| G-4 | **探测结果的失败三分法**：返回 IP 不在白名单（亲眼看到脏出口）→ 立即阻断，无容忍；探测不可达（超时/echo 挂了，"看不见"≠"看到脏的"）→ 只告警，连续 M 次才升级阻断（防单次网络抖动误杀活跃 Claude 会话） | 单次 echo 超时不触发阻断（放行态下）；返回脏 IP 时无论第几次立即阻断 |
| G-5 | 探测使用与 claude.ai 相同代理路径的 echo 端点，不直连 Claude 域名（避免阻断态死锁） | 阻断态下探测仍可正常工作 |
| G-6 | 快慢双路径：快路径（1s，纯本地：mihomo 进程/TUN 网卡）任一失败 → 立即阻断；慢路径（5s，网络：echo/fake-ip）按 G-1/G-4 逻辑 | Clash 死亡由快路径 ≤2s 捕获；网络类异常按慢路径节奏 |

### 3.3 漂移监控需求

| 编号 | 需求 | 验证标准 |
|---|---|---|
| D-1 | 每小时通过 DoH（1.1.1.1）解析 claude.ai / api.anthropic.com / anthropic.com，检查解析结果是否仍在封禁段内 | 人为改配置的段（测试环境）触发告警 |
| D-2 | 每天一次查询 RIPE stat API（AS399358 announced-prefixes），diff 前缀列表 | 新前缀出现 → 托盘黄灯 + Toast |
| D-3 | 漂移告警不自动改规则，只通知用户人工决策 | 告警态下规则状态不变 |
| D-4 | DoH 查询与 RIPE 查询失败不影响主门禁循环 | 断网时主循环照常 |

### 3.4 托盘 UI 需求

| 编号 | 需求 | 验证标准 |
|---|---|---|
| T-1 | 托盘图标三态：绿=放行 / 红=阻断 / 黄=漂移告警 | 各状态切换时图标即时更新 |
| T-2 | 悬停提示显示当前状态摘要（出口 IP、检查项结果） | 鼠标悬停可见 |
| T-3 | 菜单：状态详情 / 临时放行(30 分钟 override) / 暂停守护 / 编辑白名单 / 退出 | 全部菜单项可用 |
| T-4 | 状态变化时 Windows Toast 通知 | 放行↔阻断切换时弹通知 |
| T-5 | override（临时放行）带审计日志（只记时间/时长；原因选项不做） | 日志文件可查（时间、时长） |
| T-6 | 退出即恢复阻断并清理（规则保持 Enabled，进程退出） | 退出后 Claude 不可达 |

### 3.5 部署需求

| 编号 | 需求 | 验证标准 |
|---|---|---|
| P-1 | 单文件 exe（PyInstaller + uac-admin 自提升管理员） | 双击运行弹 UAC 后正常工作 |
| P-2 | 开机自启（计划任务，最高权限） | 重启后工具自动运行 |
| P-3 | 全部配置（白名单、IP 段、echo 端点、周期参数）外置 config.json | 改配置无需重新打包 |
| P-4 | 日志：主循环状态变化、override、漂移事件、错误，按天滚动 | 可排障 |

## 4. 环境事实（已实测，开发前提）

| 事实 | 值 |
|---|---|
| 操作系统 | Windows 10/11 x64 |
| 代理 | Clash Verge（verge-mihomo.exe）+ TUN + fake-ip（198.18.0.0/15） |
| 本机 IPv6 | 已关闭；但防误启用，IPv6 段独立规则永久封死（B-6） |
| Anthropic IPv4 段 | 160.79.104.0/23（AS399358，RIPE 权威） |
| Claude 域名 | claude.ai / api.anthropic.com / anthropic.com / console.anthropic.com → 均解析到 160.79.104.10 |
| echo 端点 | www.cloudflare.com/cdn-cgi/trace（主）、api.ip.sb（备）|
| 访问 Claude 的进程 | msedge.exe（网页版）、omp.exe（AppData\Local\omp\omp.exe，OAuth 直连 api.anthropic.com）、node.exe（Claude Code）——**全局阻断后无需逐进程枚举** |
| 开发环境 | Python 3.13 / Go 1.25 / Node 26 / VS Code 均已安装 |

## 5. 用户工作流

```
开机 → 工具自启（管理员） → CG-Global Enabled / CG-V6 永久 Enabled（阻断态，红灯）
用户开 Clash → 快路径(1s)确认本地存活；慢路径(5s)四项检查
  全过(N 次连续) → CG-Global Disable（放行，绿灯，Toast "Claude 已放行"）
  任一失败 → 保持阻断（红灯）
用户打游戏关 Clash → 快路径 1–2s 内捕获 → CG-Global Enable（红灯，Toast "Claude 已阻断"）
用户忘了开 Clash 启动 Claude → 连接被内核拒绝，零泄漏，Toast 告警
任何时刻经 IPv6 直连 Claude → 被 CG-V6 永久拦截（无状态、无例外）
漂移事件（IP 段变化）→ 黄灯 + Toast，人工决策
```

## 6. 非目标（明确排除）

- **不做**设备指纹/时区伪装检测（非 IP 维度风控信号，不在防线内）
- **不做**自动更新封禁段（漂移只告警，人工确认后改 config）
- **不做**跨机器部署/远程管理（单机个人工具）
- **不做**UDP/WebRTC/DNS 泄漏的主动检测。等效性说明：原讨论中的三类泄漏检测，其**最终危害**都是"Claude 流量以非预期出口/IP 暴露"。本方案不检测泄漏路径本身，而是直接门控危害结果——①Clash 关闭/被绕过 → 快路径 1s 捕获（覆盖 WebRTC/UDP 绕过的主渠道）；②DNS 覆写失效（fake-ip 检查）→ 慢路径捕获；③出口 IP 变化 → echo 白名单比对捕获。任何泄漏路径只要导致流量不走白名单出口，就会被门禁拦截，无需逐一枚举泄漏方式
- **不做**杀进程（防火墙事前拦截已完全取代）
- **不防**轮询窗口内的瞬时脏请求（快路径 ≤2s / 慢路径 ≤5s+RTT）与漂移发现延迟（≤1h）——架构固有残余，见架构文档 §8

## 7. 验收标准（端到端场景）

1. Clash 正常 + 出口白名单内：Claude 三种方式全部可用（绿灯）
2. 关闭 Clash：FAST_FAIL 端到端 ≤1.5s 内 Claude 全部不可达（快路径 + netsh 快车道，红灯 + Toast；秒表口径：从结束 mihomo 进程到 Claude 连接被拒）
3. 忘开 Clash 启动 Claude：连接直接失败，零流量出站
4. Clash 开启但出口 IP 不在白名单：保持阻断，托盘提示原因
5. 托盘 override：30 分钟内放行，自动恢复阻断，日志有记录
6. 强杀工具进程：阻断保持（fail-closed）
7. 改封禁段配置中的域名为一个未覆盖 IP：1 小时内黄灯告警
8. 重启机器：工具自启，规则恢复阻断态
9. （若可测）临时启用系统 IPv6 并尝试直连 claude.ai 的 v6 地址：被 CG-V6 拦截
