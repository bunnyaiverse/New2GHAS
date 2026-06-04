$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$OutputPath = ".\training\secrets-demo\live-demo-secrets.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

$awsKey = "AKIA" + "IOSFODNN7EXAMPLE"
$githubToken = "g" + "hp_" + ("0" * 36)
$slackToken = "xo" + "xb-" + "000000000000-000000000000-000000000000-fakefakefake"

@(
  "Fake values for scanner demonstrations only.",
  "AWS_ACCESS_KEY_ID=$awsKey",
  "GITHUB_TOKEN=$githubToken",
  "SLACK_BOT_TOKEN=$slackToken"
) | Set-Content -Encoding UTF8 $OutputPath

Write-Host "Created fake demo secret file at $OutputPath."
Write-Host "The file is ignored by git. Remove the ignore rule only in a temporary demo branch."
