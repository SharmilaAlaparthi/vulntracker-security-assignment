# Security Findings — VulnTracker

Findings from automated scans (Bandit SAST, pip-audit SCA, Checkov IaC, Trivy container) plus manual review. Severity reflects **this application's** context (an internal security-team tool holding vulnerability data and auth credentials), not just generic CVSS.

Raw tool output is in [`../reports/`](../reports/).

## Summary table

| # | Finding | Tool / Scan | Severity | Location | Where | Status |
|---|---------|-------------|----------|----------|-------|--------|
| 1 | SQL injection in scan search | Bandit B608 (SAST) + manual | **Critical** | `app/database.py` `search_scans_by_query` | Starter | Fixed |
| 2 | JWT `alg=none` accepted → auth bypass | Manual | **Critical** | `app/auth.py` `decode_token` | Starter | Fixed |
| 3 | Hardcoded secrets (JWT key, DB password, admin API key) | Bandit B105 (SAST) + manual | **High** | `app/config.py` | Starter | Fixed |
| 4 | Vulnerable dependency `cryptography 38.0.1` (16 known CVEs) | pip-audit (SCA) | **High** | `requirements.txt` | Starter | Fixed |
| 5 | Broken object-level authorization (IDOR) on `GET /scans/{id}` | Manual | **High** | `app/main.py` | Starter | Fixed |
| 6 | Reflective CORS with `Allow-Credentials: true` | Manual | **High** | `app/main.py` CORS middleware | Starter | Fixed |
| 7 | Plaintext password logging on every login | Manual | **High** | `app/main.py` `login` | Starter | Fixed |
| 8 | Internal detail / stack-trace leakage in error responses | Manual | Medium | `app/main.py`, `notify/src/index.js` | Starter | Fixed (app); deferred (notify) |
| 9 | Vulnerable transitive deps: `python-jose`, `starlette`, `python-multipart` | pip-audit (SCA) | Medium/High | `requirements.txt` | Starter | Partially fixed |
| 10 | Share link — token entropy / expiry / password handling | Manual (new feature) | High if done wrong | `app/main.py`, `app/models.py` | **New feature** | Implemented securely |
| 11 | `notify` — vulnerable `axios 0.21.1` (SSRF / CVE-2021-3749) | Manual / SCA | High | `notify/package.json` | Starter | Deferred (out of scope) |
| 12 | `notify` `/notify` has no authentication; webhook SSRF fan-out | Manual | Medium | `notify/src/*` | Starter | Deferred (documented) |
| 13 | IaC: image not pinned by digest, `imagePullPolicy` not `Always`, secrets-as-env | Checkov (IaC) | Low/Medium | `helm/` | New | Documented |

---

## Detailed findings

### 1. SQL injection in scan search — Critical
`search_scans_by_query` built raw SQL with an f-string, interpolating the user-supplied `q` parameter directly into `WHERE ... LIKE '%{query}%'`. Bandit flagged it as `B608`. **Business impact:** this table holds every vulnerability finding for every customer/team, plus `owner_id` linkage. A single crafted `q` (e.g. `' UNION SELECT ... --`) could exfiltrate all findings across all tenants or, via stacked queries, tamper with data — a full confidentiality and integrity breach of the exact data the product exists to protect.
**Fix:** rewrote the query with bound parameters (`:like`, `:owner_id`), escaped LIKE wildcards, and scoped results to the authenticated owner. See `app/database.py`.

### 2. JWT `alg=none` auth bypass — Critical
`decode_token` passed `algorithms=[ALGORITHM, "none"]` to `jwt.decode`. The `none` algorithm means "no signature". An attacker could craft an unsigned token with any `sub` (e.g. an admin's username) and be fully authenticated. **Business impact:** complete authentication bypass — impersonate any user, read/modify/delete any scan. This is the highest-impact issue because it defeats every access control at once.
**Fix:** `algorithms=[ALGORITHM]` only; `config.py` additionally refuses to boot if `JWT_ALGORITHM` is `none`. A regression test (`test_alg_none_token_is_rejected`) forges an unsigned token and asserts 401.

### 3. Hardcoded secrets — High
`config.py` embedded the JWT signing key, a DB password, and an "admin API key" as string literals (Bandit `B105`). **Business impact:** anyone with repo read access (or anyone who finds the public repo) can forge valid JWTs and authenticate as any user, because the signing key is known. Secrets in git history are effectively permanently compromised.
**Fix:** all secrets now come from environment variables (`app/config.py` + `.env.example`); production refuses to start without `SECRET_KEY`; dev uses an ephemeral random key. The literals were removed from source.

### 4. Vulnerable `cryptography 38.0.1` — High
pip-audit reported 16 known vulnerabilities for this pinned version (e.g. `GHSA-v8gr-m533-ghj9`, `GHSA-jm77-qphf-c4w8`, several NULL-deref / DoS and cipher issues). **Business impact:** `cryptography` underpins TLS and JWT crypto; known flaws can enable DoS or weaken cryptographic guarantees on a security product.
**Fix:** bumped to `cryptography==43.0.1` in `requirements.txt`.

### 5. IDOR on `GET /scans/{id}` — High
`get_scan` looked up a scan by `id` only, with no owner filter, while `list`, `update`, and `delete` all filtered by owner. **Business impact:** any authenticated user could read any other user's/team's findings by iterating integer IDs — a cross-tenant confidentiality break.
**Fix:** added `owner_id == current_user.id` to the query; returns 404 otherwise. Test: `test_cannot_read_another_users_scan_by_id`.

### 6. Reflective CORS with credentials — High
The custom middleware echoed any `Origin` back in `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`. **Business impact:** this configuration lets *any* website make authenticated cross-origin requests using a logged-in user's credentials — effectively defeating same-origin protection and enabling CSRF-style data theft.
**Fix:** replaced with FastAPI `CORSMiddleware` restricted to an explicit `CORS_ALLOWED_ORIGINS` allowlist (empty by default). See `app/main.py`.

### 7. Plaintext password logging — High
`login` logged the submitted username **and password** at INFO on every attempt, and again on failure. **Business impact:** credentials land in plaintext in application logs, log aggregators, and backups — a large secondary exposure surface and a compliance failure (PCI/GDPR/SOC2). Failed-login logging is where victims' mistyped real passwords often appear.
**Fix:** log only the username; never the password. See `app/main.py`.

### 8. Internal detail leakage in errors — Medium
The FastAPI global handler returned `str(exc)`, the exception type, and a full `traceback` to the client. `notify` returned `err.message` and `err.stack`. **Business impact:** leaks internal file paths, library versions, and SQL fragments that accelerate an attacker's reconnaissance.
**Fix (app):** handler now logs server-side and returns a generic `{"detail": "Internal server error"}`. **notify** left as documented deferral (assignment says notify needs no changes).

### 9. Vulnerable transitive/direct deps — Medium/High
pip-audit also flagged `python-jose` (3), `starlette` (7), `python-multipart` (8), `anyio`, `ecdsa`, `pytest`. **Business impact:** `python-jose`/`starlette`/`multipart` are on the request/auth path. **Status:** partially addressed — `cryptography` bumped (the highest-count item). The rest are documented in the remediation plan because upgrading `starlette`/`python-jose` risks breaking the pinned FastAPI version and needs a compatibility pass.

### 10. Share-link feature (new) — security-critical by design
The new share feature could easily introduce vulnerabilities (guessable tokens, no expiry, plaintext passwords, leaking owner data). Designed defensively: 256-bit CSPRNG token (`secrets.token_urlsafe(32)`), 24h expiry enforced server-side, optional password stored only as a bcrypt hash and checked in constant time, ownership enforced on creation, invalid/expired tokens return 404 (no token-existence oracle), and the public view omits `owner_id` and internal `remediation_notes`. This is the Task 1 code where a Task 3 fix (owner scoping + data minimisation) also lives.

### 11–12. notify service — deferred
`axios 0.21.1` (SSRF, CVE-2021-3749) and the unauthenticated `/notify` endpoint are real issues but the brief states the notify service requires no changes; documented with residual risk in the remediation plan.

### 13. IaC hardening — Low/Medium
Checkov (85 passed / 4 failed) flagged: image not pinned by digest (`CKV_K8S_43`), `imagePullPolicy` not `Always` (`CKV_K8S_15`), prefer secrets-as-files over env vars (`CKV_K8S_35`), and NetworkPolicy association (`CKV2_K8S_6`, an artifact of scanning the rendered Deployment in isolation — the chart does ship `networkpolicy.yaml`). Documented with remediation guidance in the remediation plan.
