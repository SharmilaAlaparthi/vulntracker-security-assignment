# Remediation Plan

This documents what was fixed, and for everything **not** fully fixed: the residual risk, the effort to remediate, and any compensating controls.

## Fixed in this submission

| Finding | Fix | Verified by |
|---------|-----|-------------|
| SQL injection (search) | Parameterised query + LIKE-wildcard escaping + owner scoping | `test_search_is_sql_injection_safe`, `test_search_is_scoped_to_owner` |
| JWT `alg=none` bypass | Removed `none` from allowed algorithms; config refuses `none` | `test_alg_none_token_is_rejected` |
| Hardcoded secrets | Env-driven config; prod requires `SECRET_KEY`; `.env.example` | Manual + `config.py` boot check |
| `cryptography 38.0.1` CVEs | Upgraded to `43.0.1` | pip-audit re-run clean for this package |
| IDOR on `GET /scans/{id}` | Owner-scoped query, 404 otherwise | `test_cannot_read_another_users_scan_by_id` |
| Reflective CORS + credentials | Allowlist via `CORSMiddleware` | Manual review |
| Plaintext password logging | Log username only | Manual review |
| Error/stack-trace leakage (app) | Generic 500 body; detail logged server-side | `test_error_response_has_no_traceback` |
| Share feature security | CSPRNG token, 24h expiry, bcrypt password, data minimisation | Full share test suite |

## Deferred / not fully remediated

### D1. `notify` service: vulnerable `axios 0.21.1` (SSRF, CVE-2021-3749)
- **Residual risk:** Medium. A malicious/compromised webhook URL could trigger SSRF via the outbound axios call. Impact is limited because webhook URLs are registered by authenticated internal users.
- **Effort:** Low — bump `axios` to a `1.x` release and run `npm test`. ~30 min.
- **Why deferred:** the brief explicitly states the notify service requires no changes; changing it risks scope creep and the Node test suite cannot be run in this environment (Node.js not installed here).
- **Compensating controls:** run notify only on an internal network segment; egress-restrict it so it can only reach approved webhook hosts.

### D2. `notify` `/notify` endpoint is unauthenticated
- **Residual risk:** Medium. Any caller with network access can trigger webhook dispatch (fan-out abuse / SSRF pivot).
- **Effort:** Medium — add a shared-secret header check or mTLS between the Python API and notify. ~1–2 hrs.
- **Why deferred:** out of the assignment's stated scope for notify; also needs coordinated change on the caller side.
- **Compensating controls:** NetworkPolicy so only the API pods can reach notify; the API already sends only trusted, server-generated payloads.

### D3. Remaining vulnerable Python deps (`python-jose`, `starlette`, `python-multipart`, `ecdsa`, `anyio`)
- **Residual risk:** Medium. Several are on the auth/request path (`python-jose` for JWT, `starlette` under FastAPI).
- **Effort:** Medium — upgrading `starlette`/`python-jose` likely forces a FastAPI bump and a regression pass across all endpoints and tests. ~2–4 hrs with careful pinning.
- **Why deferred:** the assignment pins `fastapi==0.104.1`; a coordinated framework upgrade is a separate, testable change rather than a rushed bump that could break the API contract the tests assert.
- **Compensating controls:** the specific high-risk crypto library (`cryptography`) was upgraded; input validation and the `alg` allowlist reduce exploitability of `python-jose` issues; WAF/rate limiting recommended in production.

### D4. IaC hardening items from Checkov
- **Residual risk:** Low. Pin image by digest (`CKV_K8S_43`), set `imagePullPolicy: Always` (`CKV_K8S_15`), and prefer mounting secrets as files (`CKV_K8S_35`).
- **Effort:** Low — values/template tweaks. ~30 min.
- **Why deferred:** the chart already implements the high-value controls the brief asks for (external secrets manager, restricted ingress via NetworkPolicy, resource limits, non-root security contexts). The remaining items are incremental hardening. `CKV2_K8S_6` (NetworkPolicy association) is a false positive from scanning the rendered Deployment in isolation — the chart ships `networkpolicy.yaml`.
- **Compensating controls:** NetworkPolicy, read-only root filesystem, dropped capabilities, and `runAsNonRoot` are already in place.

### D5. Rate limiting / brute-force protection on `/auth/login`
- **Residual risk:** Medium. No lockout or rate limit on login or on `GET /share/{token}` password attempts.
- **Effort:** Medium — add middleware (e.g. `slowapi`) or enforce at the ingress/API gateway. ~1–2 hrs.
- **Why deferred:** best implemented at the platform edge (ingress/WAF) rather than in app code for a prototype.
- **Compensating controls:** bcrypt makes offline cracking expensive; share tokens are high-entropy so password guessing requires first knowing a valid token.
