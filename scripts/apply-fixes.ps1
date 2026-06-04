$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

New-Item -ItemType Directory -Force -Path ".\instance" | Out-Null
@{
  mode = "fixed"
  applied_at = (Get-Date).ToUniversalTime().ToString("o")
  note = "Training fix mode enabled. Rerun scripts/run-local-scans.ps1 to refresh dashboard counts."
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 ".\instance\security-mode.json"

Copy-Item ".\requirements.fixed.txt" ".\requirements.txt" -Force

Write-Host "Fix mode enabled and requirements.txt updated from requirements.fixed.txt."
Write-Host "Run .\scripts\run-local-scans.ps1 again, then open http://localhost:5000/security-dashboard."
