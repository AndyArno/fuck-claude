<# : 2>nul
@echo off
rem ============================================================
rem  Claude Guard - firewall toggle (cmd batch header + PowerShell body)
rem  Double-click to run; auto-elevates via UAC prompt.
rem  Only use while ClaudeGuard is NOT running.
rem ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges . . .
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$raw = Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8; iex $raw"
echo.
pause
exit /b
#>

# ---------------- PowerShell 正文 ----------------
$ErrorActionPreference = "Stop"
$Rules = "CG-Global", "CG-V6", "CG-FakeIP"

Write-Host "=== Claude Guard 防火墙切换 ==="

# ① 守护在运行时拒绝执行：heal 线程会在 30 秒内把规则改回去
$proc = Get-Process -Name "ClaudeGuard" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host ""
    Write-Host "× ClaudeGuard 正在运行（PID $($proc[0].Id)）。"
    Write-Host "  请先通过托盘菜单退出守护，再运行本脚本；"
    Write-Host "  守护运行期间请直接用托盘的「暂停守护 / 临时放行」。"
    exit 1
}

# ② 收集已存在的规则（CG-FakeIP 为按需创建，可能不存在）
$existing = @()
foreach ($r in $Rules) {
    $f = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    if ($f) { $existing += $r }
}
if ($existing.Count -eq 0) {
    Write-Host ""
    Write-Host "× 未找到任何 CG-* 防火墙规则（可能从未安装或已卸载）。"
    Write-Host "  如需清理环境，请运行 uninstall.ps1；如需启用拦截，请启动 ClaudeGuard。"
    exit 2
}

# ③ 显示当前状态（任一规则启用 = 拦截中）
$blocking = $false
foreach ($r in $existing) {
    $now = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    if ($now -and "$($now.Enabled)" -eq "True") { $blocking = $true }
}
Write-Host ""
if ($blocking) {
    Write-Host "当前状态：拦截 Claude（规则已启用）"
} else {
    Write-Host "当前状态：放行 Claude（规则已停用）"
}
Write-Host ""
Write-Host "请选择操作："
Write-Host "  1. 开启拦截"
Write-Host "  2. 关闭拦截（放行）"
Write-Host ""
$choice = Read-Host "输入 1 或 2 后回车（直接回车退出）"
if ($choice -eq "1") {
    $desired = $true
} elseif ($choice -eq "2") {
    $desired = $false
} else {
    Write-Host "未选择，已退出（未做任何更改）。"
    exit 0
}

# ④ 应用到全部规则 + 逐条复查（Enable/Disable 的 -PassThru 返回切换前快照，不可信）
$failed = @()
foreach ($r in $existing) {
    if ($desired) {
        Enable-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    } else {
        Disable-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    }
    $now = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    if (-not $now -or ("$($now.Enabled)" -eq "True") -ne $desired) {
        $failed += $r
    }
}
if ($failed.Count -gt 0) {
    Write-Host "× 切换失败，以下规则未达目标状态：$($failed -join ', ')"
    Write-Host "  当前实际状态："
    Get-NetFirewallRule -DisplayName $Rules -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled | Format-Table -AutoSize
    exit 3
}

if ($desired) {
    Write-Host "√ 已开启拦截（$($existing -join ' / ') 全部启用）"
} else {
    Write-Host "√ 已关闭拦截（$($existing -join ' / ') 全部停用）"
    Write-Host "  注意：此时 Claude 流量不再受 Claude Guard 保护。"
}
