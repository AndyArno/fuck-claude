# Claude Guard 卸载脚本（需求 P 系 / dev-plan 5.4）
# 用法：管理员 PowerShell 执行：
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$TaskName = "ClaudeGuard"

Write-Host "=== Claude Guard 卸载 ==="

# ① 结束正在运行的 ClaudeGuard 进程
Get-Process -Name "ClaudeGuard" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "结束进程: ClaudeGuard (PID $($_.Id))"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

# ② 删除计划任务
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "√ 已删除计划任务 '$TaskName'"
} else {
    Write-Host "计划任务 '$TaskName' 不存在（跳过）"
}

# ③ 删除防火墙规则 CG-Global / CG-V6 / CG-FakeIP
#    （CG-FakeIP 为 fake-ip 拦截规则，按需创建，后来新增）
foreach ($rule in "CG-Global", "CG-V6", "CG-FakeIP") {
    $found = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($found) {
        Remove-NetFirewallRule -DisplayName $rule
        Write-Host "√ 已删除防火墙规则 '$rule'"
    } else {
        Write-Host "防火墙规则 '$rule' 不存在（跳过）"
    }
}

Write-Host ""
Write-Host "=== 自动清理完成 ==="
Write-Host "请手动删除程序目录（含 ClaudeGuard.exe、config.json、logs\）。"
Write-Host "（脚本不自动删除文件，避免误删你编辑过的 config.json 白名单）"
