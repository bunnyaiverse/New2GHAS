# Security Policies and Quality Gates

Security thresholds live in:

```text
security-policy.yml
```

Default policy:

```yaml
quality_gate:
  fail_on_secrets: true
  max_high_sast: 0
  max_high_dependencies: 0
  max_open_findings: 0
```

## Workflow

`.github/workflows/security-gate.yml` runs on the self-hosted Windows runner and calls:

```powershell
.\scripts\evaluate-security-gate.ps1
```

The gate fails when:

- Any open secret finding exists
- Any high or critical SAST finding exists
- Any high or critical dependency finding exists
- Any open finding exists when `max_open_findings` is zero

## Branch Protection Guidance

In GitHub branch protection rules, require these checks before merge:

- CodeQL SAST
- Secret Scanning Demo
- Security Quality Gate

For a live organization rollout, also require:

- Dependabot alerts enabled
- Code owners review
- Pull request review before merge
- No bypass for admins unless your governance process requires it
