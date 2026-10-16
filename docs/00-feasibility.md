# 可行性评估：本地 Claude 泄漏监测 + 阻断工具

## 结论（TL;DR）

**整体可行，但按模块可行性差异极大：**

| 模块 | 可行性 | 说明 |
|---|---|---|
| Claude 出口 IP 监测 | ✅ 高（本地实现非常直接） | curl 一条命令即可拿到 |
| IP 纯净度评估 | ⚠️ 中（本地无数据，依赖第三方） | 风险数据库是核心瓶颈 |
| DNS 泄漏监测 | ✅ 中高 | 完全可本地实现 |
| WebRTC 泄漏监测 | ⚠️ 中（浏览器问题，工具类应用有限） | 本地程序无"WebRTC"可测 |
| 自动阻断（杀进程 / 拦截） | ⚠️ 可行但体验差 | 可实现，但有更好的替代方案 |

---

## 一、ip.net.coffee 的检测原理（逆向分析）

### 1. Claude 出口 IP 检测

```bash
curl https://claude.ai/cdn-cgi/trace
# ip=203.0.113.10  ← 你的出口 IP
# colo=LAX loc=US   ← 命中的 Cloudflare 节点
```

Claude 域名在 Cloudflare 后面，`/cdn-cgi/trace` 是 **Cloudflare 标准端点**，它会把"发起请求的客户端 IP"回显给你。因为它只反映"你→claude.ai"这条路径的 IP，所以是判断 Claude 所见 IP 的**直接证据**，比通用"查我的IP"更准（能暴露分流不一致）。本机实测返回 IP 与 anthropic.com 一致，均为 LAX 节点。

### 2. IP 纯净度（Trust Score、住宅/机房、Tor、滥用记录）

这些**不是 Cloudflare 提供的**，是站方后端拿你的 IP 去查风险情报库：
- **Scamalytics**（滥用/fraud score，实测 `scamalytics.com/ip/<ip>` 直接可查，返回 Low Risk 等评分）
- **ip-api / ipinfo / MaxMind**（ASN、住宅 vs 机房 `hosting` 标志、地理位置）
- **Tor 节点列表**（Tor Bulk Exit List，公开可下载）
- **代理/VPN 标志**（ipinfo privacy detection、IP2Location PX 等商业库）

### 3. DNS 泄漏检测

标准手法：页面让你解析**多个随机子域**（如 `abc123.example-dns.com`），其权威 NS 服务器记录是哪台递归服务器来查询的（即 DNS 出口 IP）。若出口 IP 是本地运营商而非代理节点 → 泄漏。关键细节：**必须测多个服务商**，因为分流规则可能让 8.8.8.8 走 A 线、1.1.1.1 走 B 线，单点测试会漏判。

### 4. WebRTC 泄漏检测

浏览器 JS 调 `RTCPeerConnection` + `createDataChannel`，向多个 STUN 服务器（Google、Cloudflare）发 UDP，从响应里收集 `srflx`（server-reflexive，即公网映射）地址。如果 STUN 看到的 IP ≠ TCP 代理出口 IP → UDP 绕过了代理。该站特别指出：**代理模式（HTTP/SOCKS）下 STUN 发不出去，"无泄漏"是假象；TUN 模式下测的才是真实 UDP 出口** —— 这是该站比一般检测站细的地方。

---

## 二、你的想法逐项评估

### 2.1 本地监测 Claude 出口 IP ✅ 容易，且效果最好

这是全方案中最扎实的部分，10 分钟就能做出原型：

```
周期任务（如每 30s）：
  curl claude.ai/cdn-cgi/trace → 提取 ip=, colo=
  对比上次结果 → 变化则记录 + 评估新 IP
```

无需浏览器，Windows 上 PowerShell `Invoke-WebRequest` 或 Python `requests` 即可。建议同时测 `anthropic.com/cdn-cgi/trace`，验证两个域名是否分流一致。

### 2.2 IP 纯净度评估 ⚠️ 核心瓶颈：本地无数据

纯净度无法纯本地判断，必须查外部库。选项：

| 方案 | 数据质量 | 成本 | 限制 |
|---|---|---|---|
| Scamalytics 网页抓取 | 高（社区公认 Claude 风控参考） | 免费 | 无官方 API（有付费 API，$24.95+/月起），抓取违反 ToS |
| ip-api.com 免费 API | 中 | 免费 | 45 req/min 限流，无滥用/VPN 标志（付费版有） |
| IPinfo Privacy Detection | 高 | 免费额度 1000/月 | 标志 VPN/proxy/Tor/hosting |
| MaxMind GeoLite2（本地库） | 中 | 免费 | **本地可跑**，含 ASN，但无 abuse/fraud 数据 |
| ipinfo IP2Location 等商业库 | 很高 | 付费 | 不限速，可本地部署 |

**务实的组合**：ip-api / IPinfo 判住宅+ASN（"机房 IP"是高风险信号），Scamalytics 分数做滥用参考，Tor Exit List 本地比对。**免费方案有速率限制**，若每 30 秒全量查一次会撞墙 —— 建议策略：出口 IP 变化时才查纯净度，或结果缓存（IP 纯净度不会分钟级变化）。

[INFERENCE] 注意：Anthropic 的实际风控标准不公开，"纯净度分"只是社区经验代理指标（Scamalytics 低分 ≈ 更安全是社区共识，非官方保证）。

### 2.3 本地 DNS 泄漏监测 ✅ 可行，思路要转换

网页版的"随机子域 + 权威 NS 记录来源"需要你自建权威 NS。本地工具更直接的做法：

1. **DNS 出口探测**：向 8.8.8.8 / 1.1.1.1 / 9.9.9.9 等多个公共递归发查询，并测它们走的是哪条路 —— 但递归服务器不会告诉你"谁在问我"。
2. **更实用的本地判据**（不需要自建 NS）：
   - 抓包看 53 端口流量是否发往了"非预期"的 DNS 服务器（本地运营商 IP）
   - 对比"通过代理查的域名解析结果"与"系统直连解析结果"是否一致
3. **最准确**：本机起抓包（npcap）过滤 `udp.port==53 || tcp.port==53`，直接观察 DNS 查询的目的地址。若系统配置了代理，明文 53 出现在本地 ISP DNS → 泄漏。

需要管理员权限 + npcap（Windows）。DoH/DoT 加密后抓包只能看到"你连了哪个 DoH 服务器"，看不到查询内容——但这已经足够判断"是否走了运营商 DNS"。

### 2.4 本地 WebRTC 泄漏监测 ⚠️ 概念错位，需重新定义

WebRTC 泄漏本质是**浏览器**行为。你的本地守护进程自己没有 WebRTC 栈，无法"监测浏览器的 WebRTC"。但真正的需求其实是：**"本机 UDP 流量是否绕过了代理"**。这个可以本地测：

- 向多个 STUN 服务器发原生 UDP STUN 包（Python `stun` 库或手写，RFC 5389 就几个结构体），收集 srflx 地址
- 与 TCP 出口（`cdn-cgi/trace`）比对 → 不一致即"UDP 泄漏"
- 这正是该站 WebRTC 页的实质：WebRTC 只是触发 STUN 的载体，泄漏主体是 UDP 路径

所以：**监测"UDP 出口 = STUN 探测"，可行且推荐**；对 Claude Code 场景这甚至更相关（Claude Code 是 Node 进程，本身不用浏览器 WebRTC，但它可能有其他 UDP 行为）。

### 2.5 自动阻断 ⚠️ 可实现，但推荐换思路

**杀进程**：可行但粗暴——Claude Code 被杀会丢上下文/中断任务，而且"杀进程"和"网络已泄漏出去"之间有不可消除的时间窗（检测→判定→杀掉，期间请求已发出）。

**拦截通信**（更优）：
- Windows 防火墙规则（`netsh advfirewall` 或 WFP）按目标 IP 段阻塞 node.exe / 指定进程对 anthropic 网段的访问 —— 但 Claude 在 Cloudflare 后面，**按 IP 封会误伤所有 CF 站点**；按进程封则一刀切
- **更好的方案：出口 IP 白名单防火墙**。逻辑：只有当出口 IP ∈ 已验证纯净的集合时才放行。但 Windows 防火墙按目的 IP 过滤，不按"源出口 NAT IP"（那是上游 NAT 后的事），所以实际做法是：**监测到出口劣化 → 加防火墙规则阻断 node.exe → 提醒用户**。杀进程 vs 防火墙：防火墙可逆、无数据丢失风险，推荐。

**更根本的问题（诚实提醒）**：事后阻断工具防的是"代理突然切换出口"这类**慢速劣化**（有真实价值，这是本工具的核心价值场景）；但防不了"单次请求内"的泄漏——数据包一旦发出就发出去了。检测周期越短，暴露窗口越小，30s 周期意味着最坏情况下有 30 秒的脏请求。

### 2.6 权限与工程量（Windows）

- 防火墙操作、抓包：管理员权限
- 形态建议：Windows 服务或托盘程序（Python 打包 / Rust/Go 单文件 / C# 服务）
- 工程量：核心监测逻辑小（几百行），抓包依赖（npcap）和打包分发是大头

---

## 三、推荐架构（供后续施工参考）

```
┌─ 监测层（周期 30s）────────────────────────┐
│ ① Claude 出口 IP: GET claude.ai/cdn-cgi/trace │
│ ② UDP 出口: STUN 探测 (Google/CF 各一发)       │
│ ③ DNS 路径: 抓包/53 端口 或 DoH 服务器比对      │
└──────────────┬───────────────────┘
               ▼
┌─ 评估层 ────────────────────────────────┐
│ IP 变化 → 查 ip-api(ASN/住宅) + Scamalytics(滥用) │
│ + Tor Exit List 本地比对                  │
│ 结果缓存 24h（同 IP 不重复查）              │
└──────────────┬───────────────────┘
               ▼
┌─ 响应层 ────────────────────────────────┐
│ 风险判定 → 加 WFP/防火墙规则阻断 node.exe        │
│ → 通知（toast）→ 等待出口恢复或人工确认后解除     │
└────────────────────────────────────┘
```

判定逻辑（建议）：
- **硬阻断**：出口 IP = Tor 出口 / Scamalytics High Risk / 已知滥用记录
- **告警**：机房 IP、UDP 出口 ≠ TCP 出口、DNS 走了运营商
- **放行**：住宅 IP + 低风险分 + 出口与基线一致

## 四、最终可行度判定

**可行，价值真实，但有三处需要调整预期：**

1. **纯净度评估不是"本地"的** —— 数据源全在第三方，本地能做的只有缓存和聚合。免费源有速率限制，付费 API 或自建数据是绕不开的成本/复杂度。
2. **"WebRTC 泄漏"要改成"UDP 出口探测"** —— 你真正想防的是 UDP 绕过代理，用 STUN 探测实现，与浏览器无关，且更贴合 Claude Code（Node 进程）场景。
3. **阻断用防火墙规则优于杀进程** —— 可逆、无中断风险；且要接受"事后阻断"的本质：防劣化趋势，不防瞬时泄漏。

最有价值的场景：代理节点不稳定、自动切换出口、或分流规则被改后**悄悄劣化** —— 这是人工难以察觉、工具能真正兜底的场景。

---

## 五、重新评估：固定出口 IP 白名单模型（补充）

**前提条件**：最终出口为购买的固定 ISP IP；纯净度仅在出口 IP 变化时检测；以高频监测出口 IP 变化 + 防火墙联动。

**结论：可行性从「中」升级到「高」。** 固定出口把「模糊评分」变成「白名单比对」，判定是确定性二值逻辑（`出口IP == 基线IP ?`），热路径零第三方依赖 —— 原方案两大瓶颈（API 速率限制、纯净度灰区）同时消失。

```
┌─ 高频探测层（3–5s 周期）─────────────────┐
│ GET claude.ai/cdn-cgi/trace → 提取 ip=      │
│ 与基线比对（本地，零外部依赖，<300ms）        │
└──────────────┬────────────────────┘
               ▼
      ip == 基线 ？ ──否──→ 触发防火墙规则阻断 node.exe
               │              → toast 通知 → 等待恢复或人工确认
               是
               ▼
          放行（无任何动作）
```

### 5.1 探测频率

- 单次 HTTPS GET 对 Cloudflare 静态端点，~100–300ms；每 5s 一次 ≈ 1.7 万次/天，对 CF 零负担。
- 暴露窗口 = 探测间隔 + 连接建立时间，5s 周期下最坏 ~5–6 秒脏流量，比原方案（30s + 查询延迟）小一个数量级。
- 纯净度 API 仅两个调用时机：建立基线时一次、IP 变化时一次。速率限制问题消失。

### 5.2 防火墙联动

- 预创建 `New-NetFirewallRule -Program node.exe -Direction Outbound -Action Block -Enabled No`，触发时 Enable（毫秒级），恢复时 Disable。可逆、无数据丢失。
- Claude 在 Cloudflare 后面：**只能按进程封，不能按目的 IP 封**（会误伤所有 CF 站点）。

### 5.3 基线管理（新增问题）

固定 ISP IP ≠ 永远不变（DHCP 续租、ISP 维护）。IP 变化时的流程：

```
IP 变化 → 立即阻断（fail-closed）
        → 查新 IP 纯净度（此时才调第三方）
        → 干净 → 通知用户确认 → 接受新基线 → 解除阻断
        → 脏   → 保持阻断 + 告警
```

不要自动接受新基线 —— IP 变化本身就是异常信号，人工确认成本很低。

### 5.4 故障模式区分

- **IP 不匹配** → 立即阻断（fail-closed）。
- **探测请求失败**（网络抖动、代理断开）→ 只告警不阻断（fail-open），连续 N 次失败再升级。否则一次抖动就误杀 Claude Code 会话。

### 5.5 残余风险（不可消除，可控）

1. **进程分流不一致（最关键的准确性风险）**：代理客户端若配了进程规则（Clash/sing-box `PROCESS-NAME`），探测进程与 node.exe 可能走不同出口 —— 探测"干净"但 Claude 实际走脏路。对策：claude.ai 分流规则不基于进程，或探测流量绑定与 node 相同的代理组；上线前用浏览器访问 ip.net.coffee/claude 交叉验证。
2. **In-flight 窗口**：轮询本质决定探测间隔内的脏请求无法阻止；5s 周期下可接受。
3. **代理层更彻底的方案**：固定出口若经由单一代理节点，把该节点配成**不 fallback**（严格单节点、断线即断连）= 天然 fail-closed，比"探测+防火墙"的反应式方案更根本。两者可叠加：代理层保证节点挂了不断流，本工具捕捉其余劣化场景（DNS 污染、分流规则被改、系统路由被改）。

### 5.6 更新后的检测矩阵

| 检测项 | 频率 | 依赖 | 动作 |
|---|---|---|---|
| 出口 IP 比对 | 3–5s | 无（本地比对） | 不匹配→阻断 |
| 新 IP 纯净度 | 仅 IP 变化时 | ip-api + Scamalytics | 脏→保持阻断 |
| UDP/STUN 出口 | 5–10min | 无 | 不一致→告警 |
| DNS 路径 | 5–10min | npcap 抓包 | 运营商 DNS→告警 |

### 5.7 最终形态：默认阻断（Deny-by-default）门禁模式

**触发场景**：用户打游戏时可能关闭 Clash DNS 覆写/切直连，忘记恢复就启动 Claude → 真实 IP 泄漏。此时 mihomo REJECT 规则（方案 C）完全失效——泄漏恰恰发生在"Clash 不在"的时刻。

**设计反转**：不是"检测到泄漏才阻断"（反应式），而是"**默认阻断，环境验证通过才放行**"（门禁式）：

```
默认状态：node.exe 出站阻断规则 = Enabled（Claude 先被挡住）

守护循环（3–5s）：
  ① Clash 存活？（verge-mihomo.exe 进程 + TUN 网卡存在）
  ② DNS 覆写生效？（解析任意域名返回 198.18.x.x）
  ③ 出口 IP ∈ 白名单？（curl claude.ai/cdn-cgi/trace）
  ④ 连续 N 次通过（如 3×5s=15s 确认窗）
       ├─ 全过 → Disable 阻断规则（放行）
       └─ 任一失败 → 保持 Enabled（阻断）
```

**关键性质**：

- 忘开 Clash 启动 Claude → node.exe 被内核拒绝，零窗口、事前拦截，Toast 告警；开回 Clash 后 15s 自动恢复。
- WFP 规则在内核，不依赖 Clash 存活——唯一能在"代理缺席"时仍生效的层。
- **失败模式天然 fail-closed**：守护工具崩溃 → 规则停在 Enabled → Claude 被挡而非泄漏。工具故障的最坏结果是"不能用"，不是"泄漏"。
- 规则精确到 node.exe 进程，游戏/其他应用流量完全不受影响。

**实现要点**：
1. 放行确认窗（连续 N 次通过）必须要有——避免 Clash 启动中间态（TUN 已建、出口未就绪）闪断放行。
2. 探测路径与 node.exe 一致性仍是前提；上线前浏览器访问 ip.net.coffee/claude 交叉验证。

**分工总结**：mihomo 规则管"代理在时的精确分流"，内核防火墙默认阻断管"代理不在时的兜底"。威胁模型（代理可能缺席）决定主防线必须是防火墙，且选默认阻断而非反应式。

### 5.8 三种 Claude 使用方式的统一阻断（实测补充）

**实测的三条访问路径**：

| 使用方式 | 进程 | 目标 |
|---|---|---|
| Edge 网页版 | msedge.exe | claude.ai |
| omp 接入 Claude Pro/Max | omp.exe（AppData\Local\omp\omp.exe） | api.anthropic.com + claude.ai（OAuth 也走 Anthropic 域名；二进制内嵌 https://api.anthropic.com / https://claude.ai / oauth/anthropic，直连官方 API，无中间层） |
| Claude Code | node.exe | api.anthropic.com |

**决定性发现**：claude.ai / api.anthropic.com / console.anthropic.com 已从 Cloudflare 迁至 **Anthropic 自有 ASN（AS399358）**，全部解析到 160.79.104.10。RIPE 注册的全部前缀仅三个：

```
160.79.104.0/23      # IPv4
2607:6bc0::/48       # IPv6
2607:6bc0:11::/48    # IPv6
```

**防火墙原理**：WFP 在内核 connect() 路径上按「程序路径 × 目的 IP × 端口 × 协议」匹配，命中即 BLOCK（SYN 丢弃，连接建立不起来）——事前拦截，非事后杀流量。带 -Program 的规则精确到单个 exe，不影响其他进程。

**最终规则集（进程 × IP 双维，零误伤）**：

```powershell
New-NetFirewallRule -DisplayName "CG-Edge" -Program "...msedge.exe" `
  -RemoteAddress 160.79.104.0/23,2607:6bc0::/48,2607:6bc0:11::/48 `
  -Direction Outbound -Action Block
# 同样两条：CG-omp（omp.exe）、CG-node（node.exe）
```

语义：Edge 断 Claude 不断 YouTube；omp 断 Claude 不断其他模型商；游戏零影响。Claude 迁出 CF 后按 IP 封从"不可行"变"最优解"。

**细节**：
1. 探测进程（curl/python）不在 -Program 列表 = 天然豁免，不会被自己的规则拦住。
2. IPv6 两段必须封（claude.ai 有 AAAA 记录）；Clash 关闭时原生 IPv6 可绕过 IPv4 规则。替代方案：系统级禁用 IPv6。
3. 网段/进程列表做成可更新配置——Anthropic 新增段或 Edge 改路径时只需改配置。

**放行逻辑**与 §5.7 相同：① mihomo 存活+TUN 在 ② fake-ip 生效 ③ 出口 IP ∈ 白名单 ④ 连续 N 次通过 → Disable 全部 CG-* 规则；任一失败 → 保持 Enabled。

### 5.9 全局阻断与 IP 段漂移监控（实测补充 2）

**前提更新**：本机 IPv6 已关闭 → IPv6 /48 两段可不封（封亦无害）。

**全局规则（省略 -Program 即匹配所有进程）**：

```powershell
New-NetFirewallRule -DisplayName "CG-Global" `
  -RemoteAddress 160.79.104.0/23 `
  -Direction Outbound -Action Block
```

优点：无遗漏——claude.exe 桌面客户端、其他浏览器、内嵌 Claude SDK 的 Electron 应用全覆盖。

**死锁问题与解耦设计**：WFP 中 Block 规则永远压过 Allow（WFAS 明确行为，无法用 Allow 规则豁免探测进程）。全局阻断态下，探测 claude.ai 的流量（含经 mihomo 的出站）会被自己的规则拦住 → 永远无法确认出口恢复 → 死锁。

解法：**探测目标与 Claude 解耦**——mihomo 加规则把第三方 echo 服务（如 api.ip.sb）指定到与 claude.ai 相同的代理组，探测改为查该 echo 的返回 IP：

```yaml
rules:
  - DOMAIN-SUFFIX,ip.sb,PROXY   # 与 claude.ai 同组
```

- 阻断态：echo 不在封禁段，探测正常 → 出口干净 → 放行，无死锁
- 放行态：可继续直测 claude.ai/cdn-cgi/trace 做端到端确认
- Clash 关闭：echo 走直连返回真实 IP → 不在白名单 → 保持阻断（正确）

施工时验证：`curl claude.ai/cdn-cgi/trace` 与 `curl api.ip.sb/ip` 返回 IP 必须一致，不一致说明分流未对齐。

**IP 段漂移风险**：160.79.104.0/23 是 RIPE 路由注册表中 AS399358 当前宣告的全部 IPv4 前缀（权威）。但 Anthropic 已迁移过一次（Cloudflare → 自有 ASN），/23 仅 512 地址，扩段概率高。应对——两条自动监控：

| 检查 | 频率 | 方法 | 动作 |
|---|---|---|---|
| 域名解析漂移 | 每小时 | DoH (1.1.1.1) 解析 claude.ai / api.anthropic.com / anthropic.com（绕过 fake-ip） | 落在封禁段外 → 告警 + 提示更新 RemoteAddress |
| ASN 扩段 | 每天 | stat.ripe.net 查 AS399358 announced-prefixes，diff | 新前缀 → 告警 |

漂移语义：新 IP 在段外 = 阻断出现缺口 → 立即告警（阻断已无意义，由用户人工决策），给出建议新 RemoteAddress。DoH（本地解析视角）与 RIPE（BGP 视角）互为交叉验证；理论缺口：geo-DNS 分区解析（当前单 IP 事实表明不存在）。

**最终形态**：一条 CG-Global 规则 + 门禁循环（§5.7，探测改为 echo 解耦）+ 两条慢速漂移监控。

### 5.10 echo 服务选型

无需自备域名。选型：

1. **首选 `www.cloudflare.com/cdn-cgi/trace`**：CF anycast 高可用（探测是 3–5s 心跳，echo 挂 = 误判，必须最稳）；国内直连可达（Clash 关闭时 echo 走直连必须能通，否则"Clash 关闭"退化成"探测失败"fail-open 而非 fail-closed 阻断）；无注册无限制。
2. **备胎 api.ip.sb**：双 echo 交叉，任一返回 IP 不在白名单即阻断。
3. **隐私选项**：自建 Cloudflare Worker（`*.workers.dev` 免费子域，5 行代码返回 CF-Connecting-IP，10 万次/天额度）。第三方不可见探测模式。

mihomo 规则：`- DOMAIN-SUFFIX,cloudflare.com,PROXY`（与 claude.ai 同组）。

**上线必验**：`curl claude.ai/cdn-cgi/trace` 与 `curl www.cloudflare.com/cdn-cgi/trace` 的 ip= 必须一致——一致说明分流对齐，探测有代表性；不一致说明规则没配对，探测失真。

---

## 六、施工难度评估

**总评：中低难度，无技术硬点，核心风险在联调。** 所有关键机制（防火墙行为、IP 段、echo 对齐、omp/Edge/node 访问路径）均已实测验证，无未验证假设。工作量：能用原型 1–2 天，可日常托管成品 3–5 天。

| # | 模块 | 难度 | 工作量 | 要点 |
|---|---|---|---|---|
| 1 | 防火墙规则管理 | ⭐ | 0.5d | 一条 CG-Global + Enable/Disable 切换；每次循环校验规则状态防第三方重置 |
| 2 | 门禁探测循环 | ⭐⭐ | 1d | 四项检查 + 确认窗 + 失败/不匹配分流；难点是边界态（Clash 启动中间态、echo 抖动、DNS 缓存） |
| 3 | 白名单配置 | ⭐ | 0.5d | 配置文件，承载 IP 段/豁免等可变项 |
| 4 | 漂移监控 | ⭐ | 0.5d | DoH 每小时 + RIPE 每日 diff，各十几行 |
| 5 | 通知 Toast | ⭐ | 0.5d | 原生 API 现成绑定 |
| 6 | 部署形态 | ⭐⭐⭐ | 1–2d | **全项目最大工作量**：管理员权限 + 自启 + 崩溃 fail-closed 三者交织 |

**部署形态建议**：第一版 PowerShell + 计划任务 + Toast（最快）；跑稳后可选 Python+pystray 托盘（体验最好但打包琐碎）或 Go 服务（部署最干净）。不要第一版追求成品形态。

**联调风险（按重要度）**：
1. 探测路径一致性——mihomo 显式固化 `DOMAIN-SUFFIX,cloudflare.com,PROXY` + 工具启动时自动双端点校验；用户改分流规则是最可能悄悄坏掉的地方。
2. 状态机测试——阻断/放行切换涉及防火墙+网络+定时器三方；状态机写成纯函数 + 用例驱动，防火墙操作隔离成薄层，否则联调时间超开发时间。
3. 误杀体验——放行确认窗宁短勿长，恢复后 Toast 告知，提供 unblock.ps1 应急放行 + 日志。

**不可消除残余（验收标准的一部分）**：轮询窗口 ≤5s 脏请求；IP 段漂移最长 1h 缺口；仅覆盖 IP 维度，设备指纹/时区等非 IP 信号不在防线内。

**结论：可行性高、难度中低，纯工程组装无研究性工作。实施顺序：防火墙层 → 门禁循环 → 漂移监控 → 通知/形态，每步可独立验证。**

### 6.1 修订：一步到位托盘方案

**环境实测**：Python 3.13 / Go 1.25 / Node 26 已装，选型自由。

**选型：Python + pystray + PyInstaller**。核心复杂度在状态机+探测+联调而非性能（防火墙操作是毫秒级 PowerShell 调用），Python 迭代速度在联调阶段最值钱。Go 备选（单文件 8–12MB 部署最干净但调试慢）；C# 需装 .NET SDK；Electron/Tauri 牛刀杀鸡。

**架构**：core（纯逻辑：statemachine / checks / drift，可单测）+ platform 薄层（firewall PowerShell 封装 / notify）+ tray.py（pystray 三态图标：绿=放行 红=阻断 黄=漂移告警；菜单：状态详情/手动放行 override/暂停守护/白名单编辑/退出）+ config.json。

**相对 PowerShell 版新增工作量**：托盘 UI ~1d（pystray 线程模型：托盘线程与探测线程分离、队列通信）+ override 功能 ~80 行（托盘"临时放行 30 分钟"，误杀自救，带审计日志）+ 打包权限 ~1d（PyInstaller --uac-admin 自提升、图标、依赖裁剪、开机自启任务）。

**修订工期：~6 天**（防火墙 0.5d + 门禁 1d + 漂移 0.5d + 通知/托盘 1.5d + 打包 1d + 联调 1.5d）。增加的 1.5d 全是工程杂活，无新增技术硬点。

**专属风险**：① 打包态运行时差异——最后一天做打包态全流程演练（建规则→阻断→放行→override→漂移告警）作为验收；② pystray 依赖 Pillow 版本兼容——锁定 Pillow 11 + pystray 0.19 已验证配对。

**维护性收益**：图标状态实时回答"Claude 现在为什么连不上/能不能用"，误杀 3 秒定位，PowerShell 版只能翻日志。长期跑在主力机的安全工具，可观测性值 1.5 天差价。

**结论：托盘方案 ~6 天，风险中低，无新增硬点，值得一步到位。**
