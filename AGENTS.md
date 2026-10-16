# AGENTS.md — Claude Guard 开发代理指南

给 AI 开发代理（以及未来的人类贡献者）的项目上下文。读完本文件再动手。

## 项目是什么

Windows 单机安全工具：默认阻断本机到 Anthropic IP 段的出站流量（deny-by-default），
仅当代理环境验证干净（Clash 存活 + fake-ip 生效 + 出口 IP 在白名单 + DNS 递归出口在白名单）
时才放行。威胁模型：真实 IP 泄露 → Anthropic 封号 → 巨额经济损失。
**漏拦（该阻断没阻断）的严重度远高于误拦。** 任何设计取舍先过这一条。

## 架构速览（详见 docs/02-architecture.md）

```
core/      纯逻辑层。零副作用：禁止 import requests/psutil/subprocess/pystray。
           statemachine（门禁状态机）/ checks（确认窗计数）/ policy（CLEAN/DIRTY/UNREACHABLE
           三分法）/ drift（漂移 diff）/ config（加载校验）/ messages（用户可见文案，全部收敛于此）
winplat/   副作用薄层（Windows 平台）。firewall（WFP 规则封装）/ netprobe（echo+进程+网卡）/
           dnscheck（fake-ip + DNS 出口探针）/ ripecheck / notify（Toast 异步）/ assets
           注意：目录叫 winplat 不叫 platform——曾因遮蔽 stdlib `platform` 引发
           frozen 打包风险而改名（见 6299b29），不要改回去。
guardian.py 组装层。快路径（1s，纯本地 psutil）/ 慢路径（5s，五项检查）双节拍单线程主循环；
           规则自愈跑独立 rule-heal 线程（30s 周期 + 迁移后唤醒），主循环零 PS 调用（B-7 时序）；
           drift-monitor 线程只投递事件不动规则
tray.py    pystray 托盘。与 guardian 只通过两个 queue 通信（events / commands），
           禁止跨线程直接调用
main.py / scripts/run_guardian.py   打包入口 / 开发态入口（共用 main()）
```

## 三条防火墙规则（WFP，经 PowerShell NetSecurity）

| 规则 | 封禁对象 | 生命周期 |
|---|---|---|
| CG-Global | Anthropic IPv4 段 160.79.104.0/23（AS399358 独占） | 门控：环境脏 Enabled / 干净 Disabled |
| CG-V6 | 2607:6bc0::/48, 2607:6bc0:11::/48 | **永久 Enabled，代码中不存在任何 disable 路径** |
| CG-FakeIP | claude.ai 等 4 域名当前解析到的 fake-ip 地址 | 门控，与 CG-Global 同步（施工中） |

关键语义：CG-Global 只拦"直连泄漏路径"，不拦"经代理的正常访问"；CG-FakeIP 补齐
"环境脏时让 Claude 完全不可用"（连 fake-ip 都拒，mihomo 收不到连接就不触发上游递归）。

## 硬约束（违反即事故）

1. **fail-closed**：任何异常/崩溃/强杀，规则必须停在 Enabled。禁止出现"检查失败但规则留在 Disabled"的路径。
2. **CG-V6 不可禁用**：任何代码路径都不得 disable/删除后不重建 CG-V6。
3. **DIRTY 无容忍**：出口 IP 或 DNS 出口不在白名单 → 立即阻断，无确认窗、无重试宽限。
   只有 UNREACHABLE（探测不可达，"看不见"≠"看到脏的"）走连续 5 次升级计数。
4. **探测与 Claude 解耦**：echo/akahelp 探针必须经 mihomo 同代理路径（TUN 保证），
   否则阻断态下探测被自己的规则拦死（死锁）。新探测端点先验证这一点。
5. **用户可见文案零术语**：托盘/Toast/--check 的用户可见面只写大白话
   （"出口 IP 不干净""DNS 泄漏""Clash 没在运行"），技术细节放"——技术细节——"分隔线后。
   全部文案从 core/messages.py 取，禁止散落拼接。日志文件保持技术细节不受此限。
6. **PS 子进程必须 CREATE_NO_WINDOW**（托盘 exe 无控制台，闪窗干扰用户）+ `-NoProfile -NonInteractive`。
7. **RemoteAddress 用 PS 数组字面量** `_ps_array()`（`@('a','b')`）——逗号拼接的 IPv6 CIDR 列表
   会被 NetSecurity 判非法（实测，见 8b80a11）。
8. **规则不写 `-Protocol`**（Any 协议）——TCP-only 会被 QUIC/HTTP3 绕过（claude.ai 公告 h3，实测）。
9. **退出语义**：托盘"退出"= 先 enable 规则再退出（T-6）；入口 finally 后 `os._exit(0)`
   兜底（pystray Win32 消息泵在 windowed exe 下偶发不随 icon.stop() 结束，实测）。

## 环境事实（开发前提，勿凭空假设）

- 目标机：Windows 11 x64，中文系统（PS 输出 GBK——`_run_ps` 已做 UTF-8/mbcs 双解码）
- 代理：Clash Verge + verge-mihomo.exe，TUN + fake-ip（198.18.0.0/15），
  **clash_verge_service 服务会 3 秒内复活被杀的内核**——测"关 Clash"场景必须先 Stop-Service，
  测完恢复（用户会被弹"需要更新系统服务"打扰，测试前告知）
- 本机 IPv6 已禁用；Anthropic 四域名（claude.ai/api.anthropic.com/anthropic.com/console.anthropic.com）
  均解析到 160.79.104.10
- **测试 DNS 泄漏时注意**：fake-ip 生效（检查③）≠ DNS 干净——mihomo 接住查询但上游递归
  可能走运营商/Google DNS 并带 ECS 真实网段。akahelp `whoami.ds.akahelp.net` TXT 探针
  （`ns`/`ip`/`ecs` 行）是判定依据。当前用户环境就是天然泄漏态，可直接实机验证。

## 开发工作流

```bash
# 环境（已建）
.venv/Scripts/python -m pip install -r requirements.txt   # 版本全部锁定

# 测试（改任何代码后必跑；当前 169 passed）
.venv/Scripts/python -m pytest tests/ -q

# 自检（只读，不碰防火墙；实机验证的第一手段）
.venv/Scripts/python scripts/run_guardian.py --check

# 防火墙冒烟（管理员；建规则→直连真实IP阻断验证→放行验证→清理）
.venv/Scripts/python scripts/smoke_fw.py

# 完整运行（开发态，托盘 + 守护）
.venv/Scripts/python scripts/run_guardian.py

# 打包（生成 dist/ClaudeGuard.exe，onefile + uac_admin + windowed）
.venv/Scripts/python -m PyInstaller claude-guard.spec --noconfirm
```

- **git 提交信息一律中文**，格式 `<类型>(<范围>)?: <描述>——<关键实测证据>`
  （例：`fix: PS 子进程加 CREATE_NO_WINDOW——托盘切换不再闪黑窗`）。
- **【安全红线】禁止向 git 提交任何用户敏感信息**：真实出口 IP、DNS 递归出口、
  本地网段（ECS）、节点/机场信息。此仓库曾因此全历史重写（59a0232）。
  - `config.json` 已被 gitignore 排除（真实白名单在内），**永远不要 `git add -f config.json`**；
    需要改配置 schema 时改 `config.example.json`（模板，IP 用 RFC 5737 保留地址
    203.0.113.x / 198.51.100.x）
  - 测试/文档里需要示例 IP 时只用 RFC 5737 保留地址或文档段，**禁止**复制实机输出里的真实 IP
  - 提交前自查：`git diff --cached | grep -E "63\.125|183\.232|23\.132|172\.253|103\.142"`
    （模式按已知真实 IP 维护）；子代理的实测报告属于会话产物，不入库
- 不要提交 dist/ logs/ build/（gitignore 已排除）。
- 改动 firewall.py 后必须实机验证（管理员窗口可用 `net session` 探测）：
  规则创建/三态读取/enable 假成功检测，跑 `smoke_fw.py`。
- 测试原则：core 层纯逻辑全单测；winplat 解析函数离线单测（喂样本文本，不发网络）；
  guardian 全 mock platform 层。真实网络/防火墙行为靠 --check 和 smoke 脚本实机验证。

## 已踩过的坑（新增功能前速查）

| 坑 | 后果 | 规避 |
|---|---|---|
| PS 管道 `($r \| Get-NetFirewallRule).Enabled` | AmbiguousParameterSet 且 exit 0 → 恒 False | 用 `if($r){$r.Enabled}else{'MISSING'}` |
| `Enable-NetFirewallRule` 对不存在规则 | exit 0 假成功 | enable 后必须复查 get_status |
| 逗号拼接多 CIDR 传 RemoteAddress | IPv6 列表被判非法地址 | `_ps_array()` 数组字面量 |
| 只封 TCP | QUIC/HTTP3 绕过（claude.ai alt-svc h3） | 不写 -Protocol |
| getaddrinfo 测"Clash 死没死" | fake-ip 环境下域名连接永远走 TUN，测不到 WFP | 阻断验证直连真实 IP 160.79.104.10 |
| 杀 verge-mihomo 测关停 | clash_verge_service 3s 复活内核 | 先 Stop-Service |
| detect_drift 传空列表 | 空集 diff 全量误报"已不公告" | None=不 diff，[] =明确空集 |
| 托盘 exe spawn PS 无标志 | PowerShell 黑窗闪屏 | CREATE_NO_WINDOW |
| pystray run_detached + windowed exe | 点退出后进程挂活 | exited Event + os._exit(0) 兜底 |
| `platform/` 包名 | 遮蔽 stdlib，frozen 打包命名冲突 | 已改名 winplat/ |
| PS 单次调用 ~1.6s（冷启动 13s） | tick 内同步 PS 调用拖垮 B-7 时序 | 自愈独立线程 + _fw_lock 互斥 + 入口预热 |
| win11toast `toast()` await 用户交互 | 主循环阻塞 5-25s | notify 全部 daemon 线程异步 |

## 文档地图

- `docs/01-requirements.md` — 需求真源（B/G/D/T/P 编号 + 9 条验收场景）。改行为先改这里。
- `docs/02-architecture.md` — 模块契约 + 状态机转换表 + §8 残余风险表（时序残余、
  override 窗口强杀等都记录在案，改设计先对照）。
- `docs/03-dev-plan.md` — 里程碑与测试矩阵（12 条状态机用例与 tests/test_statemachine.py 一一对应）。
- `README.md` — 用户手册（安装/卸载/三步排查/升级说明——升级需手动删旧规则重建）。
