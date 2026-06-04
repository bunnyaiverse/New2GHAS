$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$PythonCode = @'
import json
import sys
from pathlib import Path

root = Path.cwd()

def read_policy(path):
    policy = {
        "fail_on_secrets": True,
        "max_high_sast": 0,
        "max_high_dependencies": 0,
        "max_open_findings": 0,
    }
    in_gate = False
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.rstrip()
        if line.startswith("quality_gate:"):
            in_gate = True
            continue
        if in_gate and line and not line.startswith(" "):
            break
        if in_gate and ":" in line:
            key, value = [part.strip() for part in line.split(":", 1)]
            if value.lower() in {"true", "false"}:
                policy[key] = value.lower() == "true"
            elif value.isdigit():
                policy[key] = int(value)
            else:
                policy[key] = value
    return policy

policy = read_policy(root / "security-policy.yml")

def load_sarif(path):
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    findings = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            props = result.get("properties", {})
            findings.append({"type": "sast", "severity": props.get("severity", "high"), "status": props.get("status", "open")})
    return findings

def load_json(path, finding_type):
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return [{**item, "type": finding_type} for item in data.get("findings", [])]

findings = []
findings.extend(load_sarif(root / "reports" / "sast-results.sarif"))
findings.extend(load_json(root / "reports" / "secret-results.json", "secrets"))
findings.extend(load_json(root / "reports" / "dependency-results.json", "dependencies"))

high_sast = sum(1 for f in findings if f["type"] == "sast" and f.get("status") == "open" and f.get("severity") in {"high", "critical"})
open_secrets = sum(1 for f in findings if f["type"] == "secrets" and f.get("status") == "open")
high_dependencies = sum(1 for f in findings if f["type"] == "dependencies" and f.get("status") == "open" and f.get("severity") in {"high", "critical"})
open_findings = sum(1 for f in findings if f.get("status") == "open")

failed = (
    high_sast > int(policy.get("max_high_sast", 0))
    or high_dependencies > int(policy.get("max_high_dependencies", 0))
    or open_findings > int(policy.get("max_open_findings", 0))
    or (policy.get("fail_on_secrets", True) and open_secrets > 0)
)

print(json.dumps({
    "passed": not failed,
    "high_sast": high_sast,
    "open_secrets": open_secrets,
    "high_dependencies": high_dependencies,
    "open_findings": open_findings
}, indent=2))

sys.exit(1 if failed else 0)
'@

$TempFile = Join-Path $env:TEMP "ghas-training-evaluate-security-gate.py"
$PythonCode | Set-Content -Encoding UTF8 $TempFile
python $TempFile
