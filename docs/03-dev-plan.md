# Claude Guard 开发计划

版本：1.0
日期：2026-10-15
依据：docs/01-requirements.md、docs/02-architecture.md
总工期：约 6 个工作日（单人）

---

## 0. 里程碑总览

| 里程碑 | 内容 | 完成标志 | 预计 |
|---|---|---|---|
| M1 | 防火墙层跑通 | 命令行可阻断/放行 Claude | 0.5d |
| M2 | 门禁核心跑通 | 无 UI 情况下全自动阻断/放行 | 1.5d |
| M3 | 托盘成品 | 三态图标 + 菜单 + 通知 + override | 2d |
| M4 | 漂移监控 + 部署 | 漂移告警 + 单文件 exe + 自启 | 1d |
| M5 | 端到端验收 | 需求文档 §7 八项场景全过 | 1d |

每个里程碑独立可验证、可回退。M2 结束即获得"可用但无 UI"的核心价值。

## 1. 任务拆解

### M1：防火墙层（0.5d）

| 任务 | 产出 | 验证 |
|---|---|---|
| 1.1 项目骨架：git init、venv、依赖锁定（requirements.txt + 版本锁定见架构 §7）、config.json 模板 | 可运行的空壳 | `pip install -r requirements.txt` 通过 |
| 1.2 `platform/firewall.py`：**双规则**——CG-Global（IPv4 门控：create/enable/disable/status）+ CG-V6（IPv6 永久封死：create/ensure_enabled，无 disable 接口） | PowerShell 封装模块 | 手动调用：CG-Global Enable 后 Edge 打不开 claude.ai；CG-V6 建立后（若可测）v6 直连不可达 |
| 1.3 冒烟脚本 `scripts/smoke_fw.py`：建双规则→阻断验证→放行验证→**存量连接行为实测**（架构 §3.3 注）→清理 | 一次性验证脚本 | B-1/B-3/B-4/B-6 通过 |

### M2：门禁核心（1.5d）

| 任务 | 产出 | 验证 |
|---|---|---|
| 2.1 `platform/netprobe.py`：echo 双端点探测、mihomo 进程检测、TUN 网卡检测 | 探测模块 | 关 Clash 前后输出对比 |
| 2.2 `platform/dnscheck.py`：fake-ip 生效检测（getaddrinfo 判 198.18.x.x）、DoH 解析 | DNS 模块 | Clash 开/关时 fake-ip 检查翻转 |
| 2.3 `core/config.py` + `core/policy.py`：配置加载校验、白名单比对、CLEAN/DIRTY/UNREACHABLE 三分类 | 纯逻辑 | 单测：三种探测结果的分类正确 |
| 2.4 `core/checks.py` + `core/statemachine.py`：四项评估、确认窗计数、状态转换表 | 纯逻辑状态机 | **单测（重点）**：§"测试矩阵"全过 |
| 2.5 `guardian.py` 主循环组装（无 UI）：**快慢双路径调度**（fast 1s 本地 / slow 5s 网络，单线程轮转）→ 判定→转移→执行 | 命令行守护进程 | 实机跑 30 分钟：关/开 Clash 自动阻断/放行（G-1/G-3/G-6）；**杀 mihomo → 计时，≤2s 阻断（B-7）** |
| 2.6 探测死锁规避验证：阻断态下 echo 探测仍工作 | — | 阻断态手动 curl echo 端点可达（G-5） |
| 2.7 （可选）WMI 进程退出事件订阅：`__InstanceDeletionEvent` 监听 mihomo，Clash 死亡延迟 <100ms | 事件驱动快路径增强 | 杀 mihomo → 阻断 <0.5s |

**M2 测试矩阵（状态机单测必须覆盖）**：

```
1. BLOCKED + 连续3次PASS → ALLOWED
2. BLOCKED + 2次PASS后1次FAIL → 计数清零，保持 BLOCKED
3. ALLOWED + 1次FAIL → BLOCKED（立即，无确认窗）
4. ALLOWED + PROBE_UNREACHABLE ×4 → 仍 ALLOWED
5. ALLOWED + PROBE_UNREACHABLE ×5(阈值) → BLOCKED + 告警
6. OVERRIDE_START → 30min 内检查失败不阻断
7. OVERRIDE_EXPIRE → 回到正常检查
8. DRIFT_DETECTED → 仅标志位，不影响放行
9. Clash 启动中间态（check①②过③未过）→ 保持 BLOCKED
10. ALLOWED + FAST_FAIL（mihomo 消失）→ 立即 BLOCKED，无任何确认/容忍计数
11. BLOCKED + FAST_FAIL → 保持 BLOCKED（幂等，不重复通知）
12. 探测返回脏 IP（DIRTY）→ 无论当前状态、无论第几次 → 立即 BLOCKED（G-4 三分法的"无容忍"分支）
```

### M3：托盘成品（2d）

| 任务 | 产出 | 验证 |
|---|---|---|
| 3.1 图标资源：绿/红/黄三态 PNG（含漂移叠加态） | 资源文件 | 目测 |
| 3.2 `tray.py`：pystray 消息循环线程、EventQueue/CommandQueue 双向通信、三态图标切换、悬停摘要 | 托盘模块 | 状态切换时图标即时变化（T-1/T-2） |
| 3.3 菜单：状态详情（对话框列出四项检查结果）/ 临时放行 / 暂停守护 / 编辑白名单（调起 notepad）/ 退出 | 菜单功能 | T-3 |
| 3.4 `platform/notify.py`：win11toast 状态变化通知 | 通知模块 | 放行↔阻断切换弹 Toast（T-4） |
| 3.5 override 实现：CommandQueue 处理、30min 计时器、审计日志 | override 功能 | T-5 |
| 3.6 退出语义：恢复 Enabled → 清理托盘 → 进程退出 | — | 退出后 Claude 不可达（T-6） |
| 3.7 日志模块：按天滚动、30 天保留 | logging 配置 | P-4 |

### M4：漂移监控 + 部署（1d）

| 任务 | 产出 | 验证 |
|---|---|---|
| 4.1 `core/drift.py` + `platform/ripecheck.py`：DoH 每小时域名解析比对 + RIPE 每日前缀 diff，独立线程只发事件 | 漂移监控 | 测试：临时改 config 封禁段 → 1 周期内黄灯（D-1/D-2） |
| 4.2 分流对齐自检：放行态启动时探测 claude.ai 与 echo 出口一致性，不一致黄灯提示 | 校验逻辑 | 架构 §5 前提的自动化 |
| 4.3 PyInstaller 打包：`--uac-admin --onefile --icon`、spec 固化、依赖裁剪 | 单文件 exe | 双击 → UAC → 全功能（P-1） |
| 4.4 开机自启：计划任务（最高权限、延迟 30s 等网络就绪）安装脚本 | install_task.ps1 | 重启验证（P-2） |

### M5：端到端验收（1d）

| 任务 | 内容 |
|---|---|
| 5.1 打包态全流程演练 | 以 exe 形态（非开发态）执行需求 §7 全部 9 项验收场景；其中场景 2（关 Clash）用秒表计时，达标线 ≤2s |
| 5.2 边界态演练 | Clash 启动中间态、echo 主备切换（hosts 屏蔽主端点）、双端点结果不一致、白名单编辑热生效、**快路径与慢路径同时失败时以快路径为准** |
| 5.3 过夜稳定性 | 连续运行 ≥16h：无内存增长（任务管理器）、无状态抖动、日志完整 |
| 5.4 文档交付 | README（安装/卸载/故障排查：'Claude 连不上' 三步排查法）+ 卸载脚本（删规则+删任务+删程序） |
| 5.5 清理 | 删除全部冒烟/临时脚本 |

## 2. 依赖关系与并行性

```
M1 ──► M2 ──► M3 ──► M5
           └──► M4 ──►┘
```

- M3 与 M4 相互独立，可并行（单人串行按 M3→M4，因 M3 联调更重）
- 2.3/2.4（core 纯逻辑）与 2.1/2.2（platform 探测）无依赖，可并行开发
- 状态机单测（2.4）是全局质量闸门：M3/M4 任何状态问题先回这里补用例

## 3. 风险与应对（施工期）

| 风险 | 概率 | 应对 |
|---|---|---|
| pystray + Pillow 打包兼容问题 | 中 | M4 第一时间先做最小打包验证（空壳托盘 exe），不要拖到 M4 末 |
| PowerShell 子进程 UAC/执行策略差异 | 低 | 统一 `-NoProfile -ExecutionPolicy Bypass`；打包态演练覆盖 |
| Toast 在 Win10/11 行为差异 | 低 | win11toast 已抽象；异常时降级为托盘气泡 |
| echo 端点故障 | 低 | 双端点交叉 + UNREACHABLE 阈值已设计 |
| 状态机边界态联调超时 | 中 | 测试矩阵先行（2.4），联调只验集成不验逻辑 |

## 4. 工期汇总

| 里程碑 | 工期 | 累计 |
|---|---|---|
| M1 防火墙层 | 0.5d | 0.5d |
| M2 门禁核心 | 1.5d | 2d |
| M3 托盘成品 | 2d | 4d |
| M4 漂移+部署 | 1d | 5d |
| M5 端到端验收 | 1d | 6d |

缓冲：+1d（吸收 M3 UI 联调与打包问题），总计 **7 个日历日内交付概率高**。

## 5. 完成定义（DoD）

- 需求文档 §7 全部 8 项验收场景在打包态通过
- 状态机单测全绿，测试矩阵 9 项用例全覆盖
- 过夜稳定性测试通过
- README + 卸载脚本交付，冒烟脚本清理完毕
- 桌面评估文档归档至 docs/00-feasibility.md（历史调研记录）
