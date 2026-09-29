"""Application configuration.

All security-sensitive values are sourced from environment variables so that
no secrets are committed to source control. A local `.env` file (git-ignored)
is loaded automatically for development convenience; in production the same
variables are expected to be injected by the platform / secrets manager.

See `.env.example` for the full list of supported variables.
"""

import os
import secrets as _secrets
import sys

from dotenv import load_dotenv

# Load a local .env if present. In production the process environment is
# populated by the orchestrator (e.g. Kubernetes secret -> env), so this is a
# no-op there.
load_dotenv()


def _require(name: str, default: str | None = None) -> str:
    """Return an env var, falling back to `default` for non-production.

    In production (`APP_ENV=production`) a missing security-critical value is a
    hard failure — we refuse to boot with an insecure default rather than fall
    back silently.
    """
    value = os.getenv(name, default)
    if value is None or value == "":
        if APP_ENV == "production":
            raise RuntimeError(
                f"Required environment variable '{name}' is not set. "
                "Refusing to start in production with an insecure default."
            )
        return default  # type: ignore[return-value]
    return value


APP_ENV = os.getenv("APP_ENV", "development").lower()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

# JWT signing key. Never hard-coded. In non-production we generate an ephemeral
# key at startup so developers do not accidentally rely on a shared constant;
# this means tokens do not survive a restart, which is fine for local dev.
if APP_ENV == "production":
    SECRET_KEY = _require("SECRET_KEY")
else:
    SECRET_KEY = os.getenv("SECRET_KEY") or _secrets.token_urlsafe(64)

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Downstream notification service.
NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Base URL used to build shareable report links. Falls back to the dev host.
SHARE_BASE_URL = os.getenv("SHARE_BASE_URL", "http://localhost:8000")

# Share-link lifetime in hours (assignment requires 24h).
SHARE_LINK_TTL_HOURS = int(os.getenv("SHARE_LINK_TTL_HOURS", "24"))

# Comma-separated list of origins allowed to make credentialed browser
# requests. Empty by default (no CORS) — set explicitly per environment.
CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]


def _validate() -> None:
    if ALGORITHM.lower() == "none":
        # Defense in depth: never allow the unsigned "none" algorithm.
        print("FATAL: JWT_ALGORITHM must not be 'none'.", file=sys.stderr)
        raise RuntimeError("Insecure JWT algorithm 'none' is not permitted.")


_validate()
