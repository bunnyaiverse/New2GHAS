# Trainer Guide

## Suggested Class Flow

1. Import the repository into a GitHub organization.
2. Show `SECURITY.md` and discuss lab boundaries.
3. Start the app locally.
4. Open `/security-dashboard` and show the before-fix counts.
5. Trigger two OWASP routes from the browser.
6. Show the vulnerable source comments in `app.py`.
7. Run the GitHub Actions workflows on the self-hosted Windows runner.
8. Open CodeQL, Dependabot, and secret scanning results in GitHub.
9. Run `.\scripts\apply-fixes.ps1`.
10. Run `.\scripts\run-local-scans.ps1`.
11. Refresh the dashboard and discuss fixed vs open findings.

## Good Demo Pairings

- A03 SQL injection with CodeQL.
- A06 outdated dependencies with Dependabot.
- A02 fake generated secrets with secret scanning.
- A10 SSRF with CodeQL.
- Security quality gate before and after fix mode.

## Secret Demo

Generate fake scanner-demo values:

```powershell
.\scripts\create-demo-secrets.ps1
```

The generated file is ignored by git. For a controlled demo, use a temporary branch, intentionally remove the ignore rule for that file, open a pull request, show the scanner behavior, then delete the branch.
