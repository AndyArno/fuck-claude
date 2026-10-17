# Claude Guard

Windows 单机防火墙门禁：mihomo（Clash Verge）代理链路验证不通过时，自动阻断
本机到 Anthropic（Claude）IP 段的全部出站流量，防止误直连暴露真实出口导致封号。
deny-by-default、fail-closed。

> ⚠ **自用软件声明**
>
> 本工具是**作者为个人单台设备编写的自用脚本**，按作者机器的具体环境硬编码了
> 大量前提（Windows 11 中文系统、Clash Verge + verge-mihomo、TUN + fake-ip
> 198.18.0.0/15、特定的分流配置与出口白名单）。**不保障在任何其他设备上能够
> 运行或达到预期防护效果**，不提供兼容性适配、不提供使用支持。仓库公开仅作
> 存档。如果你不是作者本人，请勿在生产环境依赖它——错误配置防火墙规则可能
> 导致网络中断。

## 威胁模型与安全语义

真实 IP 泄漏 → Anthropic 封号 → 经济损失。因此**漏拦（该拦没拦）的严重度
远高于误拦**，所有设计取舍先过这一条：

- **deny-by-default**：程序未确认"走了代理"之前，防火墙规则保持阻断。
- **fail-closed**：任何异常——检查失败、探测不可达、进程崩溃/退出、第三方
  改规则——都回落到阻断态。程序退出不会自动放行（退出前先把规则置回阻断）。
- **DIRTY 无容忍**：出口 IP 或 DNS 出口判定为脏 → 立即阻断，无确认窗、无重试。
  只有"不可达"（看不见 ≠ 看到脏的）走连续 5 次升级计数。

## 工作原理

### 三条防火墙规则（WFP）

| 规则 | 封禁对象 | 生命周期 |
|---|---|---|
| `CG-Global` | Anthropic IPv4 段（160.79.104.0/23） | 门控：环境脏启用 / 验证干净停用 |
| `CG-V6` | Anthropic IPv6 段 | **永久启用**，程序没有任何停用它代码路径 |
| `CG-FakeIP` | Claude 域名当前解析到的 fake-ip 地址 | 门控，与 CG-Global 同步；fake-ip 映射变化即重建 |

关键语义：`CG-Global` 只拦"直连泄漏路径"，不拦"经代理的正常访问"（代理出口
不在封禁段）；`CG-FakeIP` 在环境脏时让 Claude 完全不可用（连 fake-ip 都拒，
mihomo 收不到连接就不会触发上游递归）。

### 五项检查（全部通过才放行）

1. mihomo 进程存活；
2. TUN 网卡存在；
3. fake-ip 生效（claude.ai 解析落在 198.18.0.0/15）；
4. echo 出口 IP 三分法：命中白名单 → 放行；落在封禁段 → 立即阻断；
   不可达 → 按阈值升级。探针端点必须与 Claude **同一分流组**
   （否则测的是别的出口）；
5. DNS 出口干净：向 `whoami.ds.akahelp.net` 发 TXT 查询，取 ECS 网段/递归
   出口，命中 `dns_whitelist` 精确段或归属国在 `dns_egress_countries`
   内 → 干净；否则 → 立即阻断（DNS 泄漏）。

放行需连续 `pass_confirm_count`（默认 3）次慢检查全过（确认窗，防抖动），
状态栏实时显示"确认中 N/M"。

### 其他机制

- **规则自愈**：独立线程 30s 周期复查规则状态，被外部改动自动纠正；
- **漂移监控**：定期经 DoH 解析 Claude 域名、查 RIPE 上 ASN 宣告段，
  发现 IP 段漂移时托盘黄色告警（只提醒，不动规则）；
- **配置热生效**：`config.json` 保存即自动重载，无需重启；
- **防火墙快车道**：规则启停优先走 netsh（约 0.3s），失败回退
  PowerShell NetSecurity；启动预热探测规则已就绪则零 PowerShell 调用，
  且地址集与配置不符时自动覆盖重建（升级改 CIDR 无需手动删旧规则）。

## 部署（作者机器）

```
ClaudeGuard.exe    主程序（单文件，双击弹 UAC 以管理员运行）
config.json        外置配置（必须与 exe 同目录）
install_task.ps1   安装开机自启计划任务（管理员）
一键切换防火墙状态.cmd  双击切换拦截/放行（自动弹 UAC；仅守护未运行时）
```

1. 全部文件放同一目录；确认 `config.json` 与 exe 同目录；
2. 双击 `ClaudeGuard.exe`，同意 UAC，托盘出现图标即正常；
3. 管理员执行 `install_task.ps1` 创建开机自启计划任务
   （登录自启、最高权限、延迟 30s 等网络就绪、崩溃自动重启最多 3 次）。

## 日常使用

### 托盘

- **左键双击**：状态详情实时窗口（防火墙状态、五项检查结果、出口 IP）；
- **右键菜单**：状态详情 / 临时放行 N 分钟（时长取自 `override_minutes`，
  期间全程审计日志，菜单项置灰防重复）/ 立即恢复阻断（仅放行期出现）/
  暂停守护（勾选标记）/ 编辑白名单（打开 config.json）/
  退出（恢复阻断）——先恢复规则阻断再退出；
- 图标三态：🔴 阻断 / 🟡 探测中·暂停·漂移·临时放行 / 🟢 放行；
  状态变化 Toast 同步提醒。

### 临时切换防火墙（守护未运行时）

双击 `一键切换防火墙状态.cmd` 在「拦截 Claude」与「放行 Claude」间整体切换
三条规则。**仅限守护未运行时**（运行中脚本拒绝执行——heal 线程会在 30s 内
改回去）。选择放行时会二次确认是否停用 `CG-V6`（IPv6 永久防线，除非明确
知道自己在做什么，否则输入非 Y 保留）。

### 卸载

管理员执行 `uninstall.ps1`：结束进程 → 删计划任务 → 删三条防火墙规则，
最后手动删除程序目录。

## 故障排查："Claude 连不上"

1. **看托盘颜色**
   - 🔴 红：五项检查未全过，正在阻断——这是设计行为；
   - 🟡 黄：检查进行中 / 暂停 / 漂移告警 / 临时放行窗口；
   - 🟢 绿：门禁认为链路正常，问题在 mihomo/节点本身；
   - 图标消失：程序未运行，`Start-ScheduledTask -TaskName ClaudeGuard`。
2. **看日志**：`logs\guard-YYYYMMDD.log`（按天滚动），搜 `ERROR`/`状态转移`，
   看五项检查哪一项失败。
3. **手动自检**（管理员）：
   ```powershell
   .\ClaudeGuard.exe --check
   ```
   只读模式不改防火墙，输出五项检查逐项结果；有检查未通过时退出码非 0。

## 配置说明（config.json）

| 字段 | 含义 |
|---|---|
| `blocked_cidrs_v4` / `blocked_cidrs_v6` | 封禁的 Anthropic IP 段（CG-Global / CG-V6） |
| `rule_name_v4` / `rule_name_v6` / `rule_name_fakeip` | 防火墙规则名（改名前先卸载旧规则） |
| `whitelist` | ④连接出口白名单 IP/CIDR，命中即放行；保存即热生效 |
| `echo_endpoints` | 探测出口 IP 的 HTTP 端点，**必须与 Claude 同分流组**；`/cdn-cgi/trace` 结尾自动按 trace 解析 |
| `dns_probe_domain` | ⑤DNS 出口探针域名（默认 `whoami.ds.akahelp.net`） |
| `dns_whitelist` | ⑤解析出口精确段白名单（缺省复用 `whitelist`），优先于国家判定 |
| `dns_egress_countries` | ⑤解析出口归属国白名单（ISO 两位码，如 `["US"]`）；配空则仅用段判定 |
| `fakeip_range` | fake-ip 网段（默认 198.18.0.0/15） |
| `mihomo_process` | mihomo 进程名 |
| `tun_adapter_keywords` | TUN 网卡名关键字（任一命中即认定存在） |
| `fast_tick_sec` / `slow_tick_sec` | 快路径（本地检查）/ 慢路径（网络探测）周期（秒） |
| `pass_confirm_count` | 连续通过 N 次慢检查才放行（确认窗） |
| `fail_unreachable_threshold` | 不可达连续 N 次升级为阻断 |
| `doh_check_interval_min` / `ripe_check_interval_hours` | 漂移监控（DoH / RIPE）周期 |
| `override_minutes` | 托盘"临时放行"时长（分钟） |
| `claude_domains` / `asn` | 漂移检测的域名列表 / RIPE 查询的 ASN |
| `log_dir` / `log_retention_days` | 日志目录 / 按天滚动保留天数 |

改白名单：托盘右键 → "编辑白名单"，保存即生效。

## 开发

需求真源、架构契约、修复计划见 `docs/`；开发约定（含安全红线、测试命令、
已踩坑表）见 `AGENTS.md`。重新打包：
`.venv/Scripts/python -m PyInstaller claude-guard.spec --noconfirm`。
