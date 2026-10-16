# Claude Guard 计划任务安装脚本（需求 P-2）
# 用法：右键"使用 PowerShell 运行"（需管理员），或管理员终端执行：
#   powershell -ExecutionPolicy Bypass -File install_task.ps1
# 行为：创建计划任务 "ClaudeGuard"，开机自启（延迟 30s 等网络就绪），
#       以最高权限运行 dist 目录下的 ClaudeGuard.exe。
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$TaskName = "ClaudeGuard"

# exe 位置：脚本所在目录（或其 dist 子目录）下的 ClaudeGuard.exe
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Candidates = @(
    (Join-Path $ScriptDir "ClaudeGuard.exe"),
    (Join-Path $ScriptDir "dist\ClaudeGuard.exe")
)
$ExePath = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ExePath) {
    Write-Error "未找到 ClaudeGuard.exe。请把本脚本与 ClaudeGuard.exe 放在同一目录（或 exe 位于 .\dist\ 子目录）后重试。"
}

# config.json 必须与 exe 同目录（P-3：外置配置）
$ConfigPath = Join-Path (Split-Path -Parent $ExePath) "config.json"
if (-not (Test-Path $ConfigPath)) {
    Write-Warning "exe 旁边没有 config.json：$ConfigPath"
    Write-Warning "请把随包分发的 config.json 复制到 exe 同目录，否则程序启动会报配置错误。"
}

# 幂等：先删旧任务
$existing = ScheduledTasks\Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "已存在同名任务，先删除重建..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    schtasks /Delete /TN $TaskName /F | Out-Null
}

$Action    = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory (Split-Path -Parent $ExePath)
$Trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Trigger.Delay = "PT30S"   # 延迟 30s，等网络/代理就绪
$Settings  = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName `
    -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal `
    -Description "Claude Guard 门禁（开机自启，最高权限，延迟 30s 等网络就绪）" | Out-Null

Write-Host "√ 计划任务 '$TaskName' 已创建"
Write-Host "  exe: $ExePath"
Write-Host "  下次登录 30 秒后自动运行（最高权限）。立即手动启动："
Write-Host "    Start-ScheduledTask -TaskName $TaskName"
