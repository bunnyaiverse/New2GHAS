# GitHub Setup

## Repository Setup

1. Create a new empty repository in your GitHub organization.
2. Push this project to the repository.
3. Open repository Settings.
4. Go to Code security and analysis.
5. Enable GitHub Advanced Security if your plan requires it.
6. Enable CodeQL code scanning.
7. Enable Dependabot alerts.
8. Enable Dependabot security updates.
9. Enable secret scanning.
10. Enable secret scanning push protection.

## Actions Setup

This repo uses self-hosted Windows runner labels:

```yaml
runs-on: [self-hosted, Windows]
```

Confirm your runner has:

- Python 3.11 or later
- PowerShell 7 or Windows PowerShell
- Git
- Network access to GitHub Actions dependencies

## Workflows

- `.github/workflows/codeql.yml` runs CodeQL and uploads dashboard reports.
- `.github/workflows/secrets.yml` runs Gitleaks as a secret scanning demo.
- `.github/workflows/security-gate.yml` evaluates `security-policy.yml`.

## Native Secret Scanning Note

Native GitHub secret scanning is enabled through repository or organization settings, not only YAML. The included Gitleaks workflow exists so training still works even before native secret scanning is fully enabled.
