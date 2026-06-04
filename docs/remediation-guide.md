# Remediation Guide

## Local Fix Mode

Run:

```powershell
.\scripts\apply-fixes.ps1
```

This does two things:

- Writes `instance/security-mode.json` with `mode: fixed`.
- Replaces `requirements.txt` with `requirements.fixed.txt`.

Then refresh reports:

```powershell
.\scripts\run-local-scans.ps1
```

Open:

```text
http://localhost:5000/security-dashboard
```

## What Changes in Fix Mode

The browser route `/lab/<owasp-id>` redirects to the fixed implementation. The dashboard marks training findings as fixed after reports are regenerated.

## Production Remediation Themes

- Replace string-built SQL with parameterized queries.
- Remove shell execution with user input.
- Block private address SSRF targets.
- Replace weak hashes with salted KDFs.
- Store secrets in GitHub Actions secrets or an approved secret manager.
- Upgrade dependencies through Dependabot PRs.
- Add branch protection and required security checks.
