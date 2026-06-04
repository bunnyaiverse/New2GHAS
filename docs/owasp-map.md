# OWASP Top 10 Map

| OWASP | Vulnerable Route | Fixed Route | Scanner Signal | Remediation |
| --- | --- | --- | --- | --- |
| A01 Broken Access Control | `/lab/a01/vulnerable?user_id=1` | `/lab/a01/fixed?user_id=1` | CodeQL and manual review | Authorize object access against the signed-in user and role. |
| A02 Cryptographic Failures | `/lab/a02/vulnerable?value=password123` | `/lab/a02/fixed?value=password123` | CodeQL and secret scanning | Replace MD5 with salted KDF and move secrets to secret stores. |
| A03 Injection | `/lab/a03/vulnerable?q=' OR '1'='1` | `/lab/a03/fixed?q=alice` | CodeQL | Use parameterized queries and avoid shell execution. |
| A04 Insecure Design | `/lab/a04/vulnerable?price=100&discount=99` | `/lab/a04/fixed?price=100&coupon=TRAINING10` | Security gate policy | Keep business rules on the server. |
| A05 Security Misconfiguration | `/lab/a05/vulnerable` | `/lab/a05/fixed` | CodeQL and review | Disable debug behavior and redact sensitive config. |
| A06 Vulnerable and Outdated Components | `/lab/a06/vulnerable` | `/lab/a06/fixed` | Dependabot | Upgrade pinned dependencies. |
| A07 Identification and Authentication Failures | `/lab/a07/vulnerable` | `/lab/a07/fixed` | CodeQL and review | Use safe login queries, strong credentials, and lockout controls. |
| A08 Software and Data Integrity Failures | `/lab/a08/vulnerable` | `/lab/a08/fixed` | CodeQL | Avoid unsafe deserialization and validate schemas. |
| A09 Logging and Monitoring Failures | `/lab/a09/vulnerable` | `/lab/a09/fixed` | Security gate policy | Log security events without writing sensitive values. |
| A10 Server-Side Request Forgery | `/lab/a10/vulnerable?url=http://127.0.0.1:5000/lab/a05/vulnerable` | `/lab/a10/fixed?url=https://example.com` | CodeQL | Use scheme validation, allowlists, and private network blocking. |

The dashboard reads `reports/` and maps findings back to these categories.
