# Claude Guard

Windows 门禁工具：mihomo（Clash Verge）未在正确代理链路时自动阻断 Claude 系出口 IP 段，
防止误直连暴露真实出口。deny-by-default、fail-closed。

## 工作原理（安全模型）

- **deny-by-default**：防火墙规则 `CG-Global`（IPv4 出站封禁 Claude 网段）/ `CG-V6`
  （IPv6 永久封死，门禁无权放行）在程序未确认"走了代理"之前保持启用（阻断）。
- **fail-closed**：任何异常——检查失败、探测不可达、进程退出、第三方改规则——
  都回落到阻断态。程序"退出"不会自动放行。
- **五项检查**：
  1. mihomo 进程存活；
  2. TUN 网卡存在；
  3. fake-ip 生效（claude.ai 解析落在 198.18.0.0/15）；
  4. echo 出口 IP 三分法：命中白名单 → 放行；落在封禁段 → 立即阻断；不可达 → 按阈值升级；
  5. DNS 出口干净（检查⑤）：向 `dns_probe_domain`（默认 `whoami.ds.akahelp.net`）发
     TXT 查询（走系统 resolver，TUN 模式下经 mihomo 路由），从回答中提取实际递归
     出口 IP。不在白名单（`dns_whitelist`，缺省复用 `whitelist`）→ 立即阻断
     （DNS 泄漏 = 出口脏，Anthropic 可借此看到真实运营商 DNS 出口）；
     探针不可达 → 计入不可达阈值，不单点要挟门禁。
- **漂移监控**：定期经 DoH 解析 Claude 域名、查 RIPE 上 ASN 宣告段，
  发现 IP 段漂移时托盘黄色告警（只提醒，不动规则）。
- **配置热生效**：托盘"编辑白名单"打开 `config.json`，保存后无需重启，
  Guardian 检测 mtime 变化自动重载（白名单、封禁段等立即生效）。

## 目录内容

```
ClaudeGuard.exe    主程序（单文件，双击弹 UAC 以管理员运行）
config.json        外置配置（必须与 exe 同目录，用户可编辑）
install_task.ps1   安装开机自启计划任务（管理员）
toggle_firewall.ps1  一键切换防火墙拦截/放行（仅守护未运行时，管理员）
```


## 从旧版本升级

若旧版本（v0.1 之前）已部署过防火墙规则：新版规则已从 TCP-only 改为
Any 协议（封 UDP/QUIC），但程序不会自动重建已存在的旧规则。
升级后请**以管理员运行一次**：

```powershell
Remove-NetFirewallRule -DisplayName 'CG-Global','CG-V6' -ErrorAction SilentlyContinue
```

然后启动新版程序，规则会自动以新语法重建。首次安装无此问题。

## 安装

1. 把以上文件放到同一个目录（建议 `C:\Tools\ClaudeGuard\`）；
   **确认 config.json 与 ClaudeGuard.exe 同目录**。
2. 双击 `ClaudeGuard.exe`，同意 UAC，托盘出现图标即运行正常。
3. 右键 `install_task.ps1` → "使用 PowerShell 运行"（需管理员），
   或管理员终端执行：
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install_task.ps1
   ```
   脚本创建计划任务 `ClaudeGuard`：登录时自启、最高权限、延迟 30 秒等网络就绪、
   崩溃后自动重启（最多 3 次）。

> 重新打包（开发者）：`.venv/Scripts/pyinstaller.exe claude-guard.spec --noconfirm`，
> 产物为 `dist/ClaudeGuard.exe`；`config.json` 不打包进 exe（需求 P-3，保持可编辑）。

## 临时切换防火墙（守护未运行时）

管理员 PowerShell 执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\toggle_firewall.ps1
```

在「拦截 Claude」与「放行 Claude」之间整体切换三条规则
（CG-Global / CG-V6 / CG-FakeIP），再运行一次即切回。
**仅限 ClaudeGuard 未运行时使用**——守护运行中脚本会拒绝执行
（其 heal 线程会在 30 秒内把规则改回去，白切）；运行期间请用托盘的
「暂停守护 / 临时放行」。

## 卸载

管理员 PowerShell 执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

脚本会：结束 ClaudeGuard 进程 → 删除计划任务 `ClaudeGuard` →
删除防火墙规则 `CG-Global`、`CG-V6`、`CG-FakeIP`。
最后**手动删除程序目录**（脚本不自动删，避免误删你编辑过的 config.json）。

## 故障排查："Claude 连不上"

三步排查法：

1. **看托盘颜色**
   - 🔴 红（阻断）：五项检查未全过，门禁正在阻断——这是设计行为。
   - 🟡 黄（探测中/暂停/漂移）：检查进行中，或配置了漂移告警（看日志确认）。
   - 🟢 绿（放行）：门禁认为链路正常，问题不在此工具（查 mihomo/节点本身）。
   - 图标消失：程序未运行。`Start-ScheduledTask -TaskName ClaudeGuard` 手动启动。

2. **看日志**：打开 `logs\guard-YYYYMMDD.log`（按天滚动），搜索 `ERROR`/`状态转移`，
   关注五项检查哪一项失败、防火墙调用是否失败（PowerShell 冷启动首次可达 13 秒）。

3. **手动自检**：管理员终端运行
   ```powershell
   .\ClaudeGuard.exe --check
   ```
   只读模式，不改防火墙。输出五项检查逐项结果 + 图标资源自检，
   逐条对照第 1 步的颜色判断根因。

## 配置说明（config.json）

| 字段 | 含义 |
|---|---|
| `blocked_cidrs_v4` | 封禁的 Claude IPv4 段（CG-Global 封这些段） |
| `blocked_cidrs_v6` | 封禁的 IPv6 段（CG-V6 全封，门禁无权放行） |
| `rule_name_v4` / `rule_name_v6` | 防火墙规则名（默认 CG-Global / CG-V6，改名前先卸载旧规则） |
| `whitelist` | 白名单出口 IP/CIDR：echo 出口命中即放行。**编辑保存即热生效，无需重启** |
| `echo_endpoints` | 探测出口 IP 的 HTTP 端点（返回出口 IP 的 URL） |
| `fakeip_range` | fake-ip 网段，用于确认 DNS 走了 TUN（默认 198.18.0.0/15） |
| `mihomo_process` | mihomo 进程名（如 verge-mihomo.exe） |
| `tun_adapter_keywords` | TUN 网卡名关键字（任一命中即认定存在） |
| `fast_tick_sec` / `slow_tick_sec` | 快路径（本地检查）周期 / 慢路径（网络探测）周期（秒） |
| `pass_confirm_count` | 连续通过 N 次慢检查才放行（防抖动） |
| `fail_unreachable_threshold` | 出口不可达连续 N 次升级为阻断 |
| `doh_check_interval_min` / `ripe_check_interval_hours` | 漂移监控（DoH / RIPE）周期 |
| `override_minutes` | 托盘"临时放行"时长（分钟），期间全程审计日志 |
| `claude_domains` | 漂移检测的域名列表 |
| `asn` | RIPE 查询的 ASN（如 AS399358） |
| `log_dir` / `log_retention_days` | 日志目录 / 按天滚动保留天数 |

改白名单：托盘右键 → "编辑白名单"（直接打开 config.json），保存即生效。
