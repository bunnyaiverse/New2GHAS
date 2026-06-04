# Self-Hosted Windows Runner

Use a lab Windows machine or VM. Do not run this intentionally vulnerable project on a production runner.

## Recommended Runner Labels

The workflows expect:

```text
self-hosted
Windows
```

## Required Tools

Install:

- Git
- Python 3.11+
- PowerShell
- Visual Studio Build Tools if your Python package installation needs native builds

## Validation

Run from the repository root:

```powershell
python --version
powershell -NoProfile -Command "$PSVersionTable.PSVersion"
.\scripts\run-local-scans.ps1
```

## Local Hosting

Start the app:

```powershell
.\scripts\start-local.ps1
```

Open:

```text
http://localhost:5000/security-dashboard
```
