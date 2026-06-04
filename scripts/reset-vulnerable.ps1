$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

New-Item -ItemType Directory -Force -Path ".\instance" | Out-Null
@{
  mode = "vulnerable"
  reset_at = (Get-Date).ToUniversalTime().ToString("o")
  note = "Training vulnerable mode restored."
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 ".\instance\security-mode.json"

Copy-Item ".\requirements.vulnerable.txt" ".\requirements.txt" -Force

Write-Host "Vulnerable training mode restored."
Write-Host "Run .\scripts\run-local-scans.ps1 to refresh dashboard counts."
