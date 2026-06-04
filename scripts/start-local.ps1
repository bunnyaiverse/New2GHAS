param(
  [int]$Port = 5000
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
  python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

$env:FLASK_RUN_HOST = "127.0.0.1"
$env:FLASK_RUN_PORT = "$Port"
Write-Host "Starting GHAS OWASP Training Platform at http://localhost:$Port"
.\.venv\Scripts\python.exe app.py
