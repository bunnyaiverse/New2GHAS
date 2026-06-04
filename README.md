# GHAS OWASP Python Security Platform

Plug-and-play GitHub Advanced Security training repository for a Python Flask application.

This project demonstrates:

- CodeQL SAST
- Dependabot dependency alerts and update pull requests
- GitHub secret scanning setup
- Gitleaks as an Actions-based secret scanning fallback
- Security quality gates
- Local dashboard showing SAST, secrets, dependency, OWASP, fixed, and open counts
- Vulnerable and fixed examples for all OWASP Top 10 categories

## Safety

This app is intentionally vulnerable. Run it only on your own laptop, lab machine, or isolated training runner. It binds to `127.0.0.1` by default and must not be exposed publicly.

## Quick Start on Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
.\scripts\run-local-scans.ps1
.\scripts\start-local.ps1
```

Open:

```text
http://localhost:5000
http://localhost:5000/security-dashboard
```

## Fix and Rescan Demo

```powershell
.\scripts\apply-fixes.ps1
.\scripts\run-local-scans.ps1
.\scripts\start-local.ps1
```

The dashboard will move findings from open to fixed and the quality gate should pass.

To reset the classroom back to the before-fix state:

```powershell
.\scripts\reset-vulnerable.ps1
.\scripts\run-local-scans.ps1
```

## GitHub Import Flow

1. Create a new empty repository in your GitHub organization.
2. Push this repository.
3. Configure a self-hosted Windows runner with labels `self-hosted` and `Windows`.
4. Enable GHAS features in repository settings.
5. Run the CodeQL SAST, Secret Scanning Demo, and Security Quality Gate workflows.

See [GitHub setup](docs/github-setup.md), [Windows runner setup](docs/self-hosted-windows-runner.md), and [security policies](docs/security-policies.md).

## Training Routes

Each OWASP category has:

- A vulnerable route
- A fixed route
- UI explanation
- Source comments
- Dashboard findings
- Remediation notes

Full mapping: [OWASP map](docs/owasp-map.md).
