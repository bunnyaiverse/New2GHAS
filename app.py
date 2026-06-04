import hashlib
import hmac
import ipaddress
import json
import logging
import os
import pickle
import secrets
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, Response, abort, g, redirect, render_template, request, session, url_for


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "training.db"
REPORTS_DIR = BASE_DIR / "reports"
MODE_PATH = BASE_DIR / "instance" / "security-mode.json"
AUDIT_LOG = BASE_DIR / "reports" / "audit.log"
UPLOAD_DIR = BASE_DIR / "uploads"

app = Flask(__name__)
app.secret_key = "training-only-hardcoded-secret-key"
app.config.update(
    DEBUG=True,
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
)

logging.basicConfig(level=logging.INFO)


OWASP_ITEMS = [
    {
        "id": "a01",
        "title": "A01 Broken Access Control",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a01/vulnerable?user_id=1",
        "fixed": "/lab/a01/fixed?user_id=1",
        "risk": "A user can request another user's profile by changing an ID.",
        "fix": "Authorize the requested resource against the signed-in user and role.",
    },
    {
        "id": "a02",
        "title": "A02 Cryptographic Failures",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a02/vulnerable?value=password123",
        "fixed": "/lab/a02/fixed?value=password123",
        "risk": "Weak hashing and hardcoded secrets make sensitive data easier to recover.",
        "fix": "Use a modern password KDF with salt and keep secrets outside source code.",
    },
    {
        "id": "a03",
        "title": "A03 Injection",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a03/vulnerable?q=' OR '1'='1",
        "fixed": "/lab/a03/fixed?q=alice",
        "risk": "Untrusted input is concatenated into SQL and shell commands.",
        "fix": "Use parameterized queries and avoid shell execution with user input.",
    },
    {
        "id": "a04",
        "title": "A04 Insecure Design",
        "scanner": "Security Gate",
        "vulnerable": "/lab/a04/vulnerable?price=100&discount=99",
        "fixed": "/lab/a04/fixed?price=100&coupon=TRAINING10",
        "risk": "The business rule lets the browser choose any discount.",
        "fix": "Move business rules server-side and allow only approved coupon values.",
    },
    {
        "id": "a05",
        "title": "A05 Security Misconfiguration",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a05/vulnerable",
        "fixed": "/lab/a05/fixed",
        "risk": "Debug mode and sensitive configuration are exposed.",
        "fix": "Disable debug mode for shared environments and redact sensitive values.",
    },
    {
        "id": "a06",
        "title": "A06 Vulnerable and Outdated Components",
        "scanner": "Dependabot",
        "vulnerable": "/lab/a06/vulnerable",
        "fixed": "/lab/a06/fixed",
        "risk": "Pinned outdated dependencies create known vulnerability exposure.",
        "fix": "Use Dependabot updates and upgrade to the fixed dependency set.",
    },
    {
        "id": "a07",
        "title": "A07 Identification and Authentication Failures",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a07/vulnerable",
        "fixed": "/lab/a07/fixed",
        "risk": "Weak default credentials and unsafe login queries weaken authentication.",
        "fix": "Use parameterized login checks, lockout controls, and strong password policy.",
    },
    {
        "id": "a08",
        "title": "A08 Software and Data Integrity Failures",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a08/vulnerable",
        "fixed": "/lab/a08/fixed",
        "risk": "Unsafe deserialization trusts attacker-controlled data.",
        "fix": "Use safe parsers and validate the expected schema before processing.",
    },
    {
        "id": "a09",
        "title": "A09 Security Logging and Monitoring Failures",
        "scanner": "Security Gate",
        "vulnerable": "/lab/a09/vulnerable",
        "fixed": "/lab/a09/fixed",
        "risk": "Authentication failures are not recorded, reducing incident visibility.",
        "fix": "Log security-relevant events without writing secrets or passwords.",
    },
    {
        "id": "a10",
        "title": "A10 Server-Side Request Forgery",
        "scanner": "CodeQL SAST",
        "vulnerable": "/lab/a10/vulnerable?url=http://127.0.0.1:5000/lab/a05/vulnerable",
        "fixed": "/lab/a10/fixed?url=https://example.com",
        "risk": "The server fetches an attacker-controlled URL.",
        "fix": "Validate schemes, use an allowlist, and block private network targets.",
    },
]


def get_mode():
    if MODE_PATH.exists():
        return json.loads(MODE_PATH.read_text(encoding="utf-8")).get("mode", "vulnerable")
    return "vulnerable"


def get_db():
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            email TEXT
        );
        """
    )
    users = [
        (1, "admin", "admin123", "admin", "admin@example.test"),
        (2, "alice", "password", "user", "alice@example.test"),
        (3, "bob", "letmein", "user", "bob@example.test"),
    ]
    for user_id, username, password, role, email in users:
        db.execute(
            "INSERT OR IGNORE INTO users (id, username, password_hash, role, email) VALUES (?, ?, ?, ?, ?)",
            (user_id, username, password, role, email),
        )
    db.commit()


@app.before_request
def prepare_request():
    init_db()


def load_sarif(path):
    if not path.exists():
        return []
    sarif = json.loads(path.read_text(encoding="utf-8-sig"))
    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            location = result.get("locations", [{}])[0].get("physicalLocation", {})
            artifact = location.get("artifactLocation", {}).get("uri", "unknown")
            region = location.get("region", {})
            props = result.get("properties", {})
            findings.append(
                {
                    "type": "sast",
                    "id": result.get("ruleId", "codeql-result"),
                    "title": result.get("message", {}).get("text", "CodeQL finding"),
                    "severity": props.get("severity", "high"),
                    "owasp": props.get("owasp", "Unmapped"),
                    "file": artifact,
                    "line": region.get("startLine", 1),
                    "status": props.get("status", "open"),
                    "remediation": props.get("remediation", "Review and replace the vulnerable pattern."),
                }
            )
    return findings


def load_json_findings(path, finding_type):
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    findings = data.get("findings", data if isinstance(data, list) else [])
    for finding in findings:
        finding.setdefault("type", finding_type)
        finding.setdefault("file", "unknown")
        finding.setdefault("line", 1)
        finding.setdefault("status", "open")
        finding.setdefault("severity", "medium")
        finding.setdefault("owasp", "Unmapped")
        finding.setdefault("remediation", "Review remediation guidance.")
    return findings


def collect_findings():
    files = {
        "sast": REPORTS_DIR / "sast-results.sarif",
        "secrets": REPORTS_DIR / "secret-results.json",
        "dependencies": REPORTS_DIR / "dependency-results.json",
    }
    if not files["sast"].exists():
        files["sast"] = REPORTS_DIR / "sample-sast.sarif"
    if not files["secrets"].exists():
        files["secrets"] = REPORTS_DIR / "sample-secrets.json"
    if not files["dependencies"].exists():
        files["dependencies"] = REPORTS_DIR / "sample-dependencies.json"

    findings = []
    findings.extend(load_sarif(files["sast"]))
    findings.extend(load_json_findings(files["secrets"], "secrets"))
    findings.extend(load_json_findings(files["dependencies"], "dependencies"))
    return findings


def summarize_findings(findings):
    summary = {
        "total": len(findings),
        "by_type": {"sast": 0, "secrets": 0, "dependencies": 0},
        "by_severity": {},
        "by_owasp": {},
        "open": 0,
        "fixed": 0,
    }
    for finding in findings:
        summary["by_type"][finding["type"]] = summary["by_type"].get(finding["type"], 0) + 1
        summary["by_severity"][finding["severity"]] = summary["by_severity"].get(finding["severity"], 0) + 1
        summary["by_owasp"][finding["owasp"]] = summary["by_owasp"].get(finding["owasp"], 0) + 1
        if finding["status"] == "fixed":
            summary["fixed"] += 1
        else:
            summary["open"] += 1
    return summary


def read_policy():
    policy_path = BASE_DIR / "security-policy.yml"
    if not policy_path.exists():
        return {"quality_gate": {"fail_on_secrets": True, "max_high_sast": 0, "max_high_dependencies": 0}}
    return yaml.safe_load(policy_path.read_text(encoding="utf-8-sig"))


def evaluate_gate(summary, findings):
    policy = read_policy().get("quality_gate", {})
    high_sast = sum(1 for f in findings if f["type"] == "sast" and f["status"] == "open" and f["severity"] in {"high", "critical"})
    open_secrets = sum(1 for f in findings if f["type"] == "secrets" and f["status"] == "open")
    high_deps = sum(1 for f in findings if f["type"] == "dependencies" and f["status"] == "open" and f["severity"] in {"high", "critical"})
    passed = (
        high_sast <= int(policy.get("max_high_sast", 0))
        and high_deps <= int(policy.get("max_high_dependencies", 0))
        and (open_secrets == 0 or not policy.get("fail_on_secrets", True))
    )
    return {"passed": passed, "high_sast": high_sast, "open_secrets": open_secrets, "high_dependencies": high_deps}


@app.route("/")
def index():
    return render_template("index.html", items=OWASP_ITEMS, mode=get_mode())


@app.route("/security-dashboard")
def security_dashboard():
    findings = collect_findings()
    summary = summarize_findings(findings)
    gate = evaluate_gate(summary, findings)
    return render_template("dashboard.html", findings=findings, summary=summary, gate=gate, mode=get_mode())


@app.route("/owasp/<item_id>")
def owasp_detail(item_id):
    item = next((entry for entry in OWASP_ITEMS if entry["id"] == item_id), None)
    if not item:
        abort(404)
    return render_template("owasp.html", item=item, mode=get_mode())


@app.route("/lab/<item_id>")
def run_selected_mode(item_id):
    return redirect(url_for(f"{item_id}_{get_mode()}"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and hmac.compare_digest(user["password_hash"], password):
            session["user"] = dict(user)
            return redirect("/")
        error = "Login failed."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/lab/a01/vulnerable")
def a01_vulnerable():
    user_id = request.args.get("user_id", "1")
    # TRAINING VULNERABLE PATTERN: object access trusts a user-controlled ID.
    user = get_db().execute(f"SELECT id, username, role, email FROM users WHERE id = {user_id}").fetchone()
    return dict(user) if user else ("No user", 404)


@app.route("/lab/a01/fixed")
def a01_fixed():
    requested_id = int(request.args.get("user_id", "1"))
    current = session.get("user", {"id": 2, "role": "user"})
    # TRAINING FIXED PATTERN: authorize the object before returning it.
    if current["role"] != "admin" and int(current["id"]) != requested_id:
        abort(403)
    user = get_db().execute("SELECT id, username, role, email FROM users WHERE id = ?", (requested_id,)).fetchone()
    return dict(user) if user else ("No user", 404)


@app.route("/lab/a02/vulnerable")
def a02_vulnerable():
    value = request.args.get("value", "password123")
    # TRAINING VULNERABLE PATTERN: MD5 is not appropriate for password storage.
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()
    return {"algorithm": "md5", "hash": digest, "hardcoded_secret_present": bool(app.secret_key)}


@app.route("/lab/a02/fixed")
def a02_fixed():
    value = request.args.get("value", "password123")
    salt = secrets.token_bytes(16)
    # TRAINING FIXED PATTERN: use a salted, slow password hashing primitive.
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 200_000).hex()
    return {"algorithm": "pbkdf2_hmac_sha256", "hash_preview": digest[:24], "salted": True}


@app.route("/lab/a03/vulnerable")
def a03_vulnerable():
    q = request.args.get("q", "")
    # TRAINING VULNERABLE PATTERN: untrusted input is concatenated into SQL.
    sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%' OR email LIKE '%{q}%'"
    rows = get_db().execute(sql).fetchall()
    return {"query": sql, "results": [dict(row) for row in rows]}


@app.route("/lab/a03/vulnerable/run")
def a03_command_vulnerable():
    host = request.args.get("host", "127.0.0.1")
    # TRAINING VULNERABLE PATTERN: shell=True with user input enables command injection.
    output = subprocess.run(f"ping -n 1 {host}", shell=True, capture_output=True, text=True, timeout=5)
    return Response(output.stdout + output.stderr, mimetype="text/plain")


@app.route("/lab/a03/fixed")
def a03_fixed():
    q = request.args.get("q", "")
    # TRAINING FIXED PATTERN: parameterized queries keep input as data.
    rows = get_db().execute(
        "SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?",
        (f"%{q}%", f"%{q}%"),
    ).fetchall()
    return {"results": [dict(row) for row in rows]}


@app.route("/lab/a04/vulnerable")
def a04_vulnerable():
    price = float(request.args.get("price", "100"))
    discount = float(request.args.get("discount", "99"))
    # TRAINING VULNERABLE PATTERN: the client controls the business rule.
    return {"original": price, "discount_percent": discount, "final": round(price * (1 - discount / 100), 2)}


@app.route("/lab/a04/fixed")
def a04_fixed():
    price = float(request.args.get("price", "100"))
    coupon = request.args.get("coupon", "")
    # TRAINING FIXED PATTERN: server-owned allowlist defines valid business outcomes.
    discounts = {"TRAINING10": 10, "TEAM20": 20}
    discount = discounts.get(coupon, 0)
    return {"original": price, "coupon": coupon, "discount_percent": discount, "final": round(price * (1 - discount / 100), 2)}


@app.route("/lab/a05/vulnerable")
def a05_vulnerable():
    # TRAINING VULNERABLE PATTERN: sensitive runtime configuration is exposed.
    return {"debug": app.config["DEBUG"], "secret_key": app.secret_key, "environment": dict(os.environ)}


@app.route("/lab/a05/fixed")
def a05_fixed():
    # TRAINING FIXED PATTERN: reveal only non-sensitive operational state.
    return {"debug": False, "secret_key": "redacted", "environment": "redacted"}


@app.route("/lab/a06/vulnerable")
def a06_vulnerable():
    return Response((BASE_DIR / "requirements.txt").read_text(encoding="utf-8"), mimetype="text/plain")


@app.route("/lab/a06/fixed")
def a06_fixed():
    return Response((BASE_DIR / "requirements.fixed.txt").read_text(encoding="utf-8"), mimetype="text/plain")


@app.route("/lab/a07/vulnerable", methods=["GET", "POST"])
def a07_vulnerable():
    username = request.values.get("username", "admin")
    password = request.values.get("password", "admin123")
    # TRAINING VULNERABLE PATTERN: SQL injection and weak default credentials.
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
    user = get_db().execute(sql).fetchone()
    return {"authenticated": bool(user), "query": sql, "hint": "Try username admin' --"}


@app.route("/lab/a07/fixed", methods=["GET", "POST"])
def a07_fixed():
    username = request.values.get("username", "admin")
    password = request.values.get("password", "")
    # TRAINING FIXED PATTERN: parameterized lookup and constant-time comparison.
    user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    authenticated = bool(user and hmac.compare_digest(user["password_hash"], password))
    return {"authenticated": authenticated}


@app.route("/lab/a08/vulnerable", methods=["GET", "POST"])
def a08_vulnerable():
    payload = request.values.get("payload", "!!python/object/apply:os.system ['echo training']")
    if request.values.get("format") == "pickle":
        # TRAINING VULNERABLE PATTERN: pickle loads attacker-controlled bytes.
        result = pickle.loads(bytes.fromhex(payload))
    else:
        # TRAINING VULNERABLE PATTERN: yaml.Loader can construct unsafe Python objects.
        result = yaml.load(payload, Loader=yaml.Loader)
    return {"result": repr(result)}


@app.route("/lab/a08/fixed", methods=["GET", "POST"])
def a08_fixed():
    payload = request.values.get("payload", '{"name": "training", "role": "student"}')
    # TRAINING FIXED PATTERN: use JSON and validate expected fields.
    data = json.loads(payload)
    allowed = {"name": str(data.get("name", ""))[:80], "role": str(data.get("role", "student"))[:40]}
    return allowed


@app.route("/lab/a09/vulnerable")
def a09_vulnerable():
    # TRAINING VULNERABLE PATTERN: security-relevant failures are intentionally not logged.
    return {"login_attempt": "failed", "logged": False}


@app.route("/lab/a09/fixed")
def a09_fixed():
    REPORTS_DIR.mkdir(exist_ok=True)
    event = {"event": "failed_login", "user": request.args.get("user", "unknown"), "time": datetime.now(timezone.utc).isoformat()}
    # TRAINING FIXED PATTERN: log the event while avoiding passwords and tokens.
    AUDIT_LOG.write_text(json.dumps(event) + "\n", encoding="utf-8")
    return {"login_attempt": "failed", "logged": True, "event": event}


def is_public_https_url(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return parsed.hostname in {"example.com", "www.example.com"}


@app.route("/lab/a10/vulnerable")
def a10_vulnerable():
    url = request.args.get("url", "http://127.0.0.1:5000/lab/a05/vulnerable")
    # TRAINING VULNERABLE PATTERN: the server fetches a fully user-controlled URL.
    response = requests.get(url, timeout=3)
    return Response(response.text[:3000], mimetype="text/plain")


@app.route("/lab/a10/fixed")
def a10_fixed():
    url = request.args.get("url", "https://example.com")
    # TRAINING FIXED PATTERN: enforce scheme, allowlist, and private-address checks.
    if not is_public_https_url(url):
        abort(400, "URL is not allowed")
    response = requests.get(url, timeout=3)
    return Response(response.text[:1000], mimetype="text/plain")


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_RUN_PORT", "5000")),
        debug=True,
    )
