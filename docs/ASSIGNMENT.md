# Security Automation Engineer — Take-Home Assignment (original brief)

> This is the original assignment brief, preserved verbatim for reference. The
> delivered solution is documented in the top-level `README.md`.

## Background
VulnTracker is a two-service system for managing vulnerability scan results:

- `app/` — Python/FastAPI REST API. Security teams use it to log findings, track remediation, and share reports with stakeholders.
- `notify/` — Node.js/Express notification service. Intended to dispatch webhook events to registered endpoints when scan records are created or updated.

Both services are working but imperfect internal prototypes. Neither has gone through a formal security review. The Python API calls the notification service in the background whenever a scan is created or updated.

Requirements: Python 3.11 (exactly — see CI), Node.js 20+, Docker.

## Tasks
- **Task 1 — Extend the App:** Implement the "Shared Report Link" feature. `POST /scans/{scan_id}/share` (Bearer token, optional password, returns `{ "share_url": "..." }`) and `GET /share/{token}` (public; if password-protected, require a `password` query parameter). Link expires after 24 hours.
- **Task 2 — Security Analysis:** Run SAST, dependency/SCA, container image, and IaC scans. Save raw JSON to `reports/`. Write `docs/findings.md` with prioritised, business-contextualised findings.
- **Task 3 — Remediate:** Fix at least 3 critical/high findings in code (at least one in the Task 1 code). Document deferrals in `docs/remediation-plan.md`.
- **Task 4 — Containerisation & Deployment:** Production Dockerfile (minimal pinned base, non-root, HEALTHCHECK, no secrets) plus a `terraform/` or `helm/` directory (secrets from a secrets manager, restricted ingress, resource limits, security contexts).
- **Task 5 — Executive Summary:** `docs/executive-summary.md` for a CISO — business risk, no jargon.

CI must pass (green) before submission.
