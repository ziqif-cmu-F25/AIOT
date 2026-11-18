# overnight_trigger.ps1
# Waits ~2 hours while keeping the system awake, then sends a message
# to the active Claude Code session to start the overnight run.
#
# Usage: right-click > Run with PowerShell, then walk away.
# Leave the Claude desktop app open with the session visible.

$waitSeconds = 7200
$keepAliveInterval = 60

$shell = New-Object -ComObject WScript.Shell
$elapsed = 0

Write-Host "Keeping system awake for $($waitSeconds / 3600) hours..."
Write-Host "Press Ctrl+C to cancel.`n"

while ($elapsed -lt $waitSeconds) {
    $remaining = [math]::Round(($waitSeconds - $elapsed) / 60)
    Write-Host "`r  $remaining minutes remaining..." -NoNewline
    $shell.SendKeys("{SCROLLLOCK}{SCROLLLOCK}")
    Start-Sleep -Seconds $keepAliveInterval
    $elapsed += $keepAliveInterval
}

Write-Host "`n`nTime's up. Sending trigger to Claude..."

$shell.AppActivate("Claude")
Start-Sleep -Seconds 3
$shell.SendKeys("Execute the full overnight autonomous run now: libcoap triage + input-drafting (cloud), libcoap C1 expansion, Ollama local models all targets, then convert all new results to schema records.")
Start-Sleep -Seconds 1
$shell.SendKeys("{ENTER}")

Write-Host "Sent. Claude should be working now."
