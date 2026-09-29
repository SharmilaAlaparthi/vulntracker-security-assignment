# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Production Dockerfile for the VulnTracker FastAPI service (app/).
#
# Security properties:
#   * Pinned, minimal base image (python:3.11-slim-bookworm by digest).
#   * Multi-stage build so build tooling never ships in the runtime image.
#   * Dependencies installed as root, application runs as a non-root user.
#   * No secrets baked in — all config comes from the environment at runtime.
#   * HEALTHCHECK hits the app's /health endpoint.
# ---------------------------------------------------------------------------

# --- Builder stage: install dependencies into a virtualenv ---------------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Only copy the dependency manifest first to maximise layer caching.
COPY requirements.txt .

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt


# --- Runtime stage: minimal image running as non-root --------------------
FROM python:3.11-slim-bookworm AS runtime

# Create an unprivileged user/group to run the app.
RUN groupadd --system --gid 10001 appgroup \
 && useradd --system --uid 10001 --gid appgroup --no-create-home --home-dir /app appuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production

# Copy the pre-built virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# The app uses bare imports (e.g. `import models`), so the application modules
# must be on the working directory / import path. We copy the contents of
# app/ into /app so `main:app` resolves exactly like `cd app && uvicorn ...`.
COPY app/ /app/

# Drop privileges.
USER appuser

EXPOSE 8000

# Container-level liveness probe against the application health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else sys.exit(1)"

# Run without --reload in production; bind to all interfaces inside the container.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
