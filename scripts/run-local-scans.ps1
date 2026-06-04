$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

New-Item -ItemType Directory -Force -Path ".\reports" | Out-Null

$ModePath = ".\instance\security-mode.json"
$Mode = "vulnerable"
if (Test-Path $ModePath) {
  $Mode = (Get-Content $ModePath -Raw | ConvertFrom-Json).mode
}

function FindingStatus {
  if ($Mode -eq "fixed") {
    return "fixed"
  }
  return "open"
}

$Status = FindingStatus

$sarif = @{
  '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
  version = "2.1.0"
  runs = @(
    @{
      tool = @{ driver = @{ name = "Local GHAS Training SAST Simulator" } }
      results = @(
        @{
          ruleId = "py/sql-injection"
          message = @{ text = "SQL query built from user-controlled data" }
          locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "app.py" }; region = @{ startLine = 376 } } })
          properties = @{ severity = "high"; owasp = "A03 Injection"; status = $Status; remediation = "Use parameterized SQL queries." }
        },
        @{
          ruleId = "py/command-line-injection"
          message = @{ text = "Shell command built from user-controlled data" }
          locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "app.py" }; region = @{ startLine = 387 } } })
          properties = @{ severity = "critical"; owasp = "A03 Injection"; status = $Status; remediation = "Avoid shell=True and validate command arguments." }
        },
        @{
          ruleId = "py/weak-crypto"
          message = @{ text = "Weak cryptographic hash used for sensitive data" }
          locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "app.py" }; region = @{ startLine = 361 } } })
          properties = @{ severity = "high"; owasp = "A02 Cryptographic Failures"; status = $Status; remediation = "Use a salted password KDF." }
        },
        @{
          ruleId = "py/unsafe-deserialization"
          message = @{ text = "Unsafe deserialization of untrusted input" }
          locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "app.py" }; region = @{ startLine = 472 } } })
          properties = @{ severity = "high"; owasp = "A08 Software and Data Integrity Failures"; status = $Status; remediation = "Use safe parsers and schema validation." }
        },
        @{
          ruleId = "py/full-ssrf"
          message = @{ text = "Server-side request forgery from user-controlled URL" }
          locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "app.py" }; region = @{ startLine = 523 } } })
          properties = @{ severity = "high"; owasp = "A10 Server-Side Request Forgery"; status = $Status; remediation = "Allowlist outbound destinations and block private network targets." }
        }
      )
    }
  )
}

$secretFindings = @{
  findings = @(
    @{ type = "secrets"; id = "demo-aws-access-key"; title = "Demo cloud access key pattern detected"; severity = "critical"; owasp = "A02 Cryptographic Failures"; file = "training/secrets-demo/live-demo-secrets.txt"; line = 2; status = $Status; remediation = "Remove from git history, rotate, and store in GitHub Actions secrets." },
    @{ type = "secrets"; id = "demo-github-token"; title = "Demo source control token pattern detected"; severity = "high"; owasp = "A02 Cryptographic Failures"; file = "training/secrets-demo/live-demo-secrets.txt"; line = 3; status = $Status; remediation = "Revoke token and enable push protection." }
  )
}

$dependencyFindings = @{
  findings = @(
    @{ type = "dependencies"; id = "demo-urllib3-old"; title = "urllib3 is pinned to a vulnerable training version"; severity = "high"; owasp = "A06 Vulnerable and Outdated Components"; file = "requirements.txt"; line = 4; status = $Status; remediation = "Apply Dependabot update or requirements.fixed.txt." },
    @{ type = "dependencies"; id = "demo-pyyaml-old"; title = "PyYAML is pinned to an outdated training version"; severity = "high"; owasp = "A06 Vulnerable and Outdated Components"; file = "requirements.txt"; line = 5; status = $Status; remediation = "Upgrade PyYAML and use yaml.safe_load." }
  )
}

$sarif | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 ".\reports\sast-results.sarif"
$secretFindings | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 ".\reports\secret-results.json"
$dependencyFindings | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 ".\reports\dependency-results.json"

Write-Host "Generated local training reports in .\reports using mode: $Mode"
Write-Host "Open http://localhost:5000/security-dashboard after starting the app."
