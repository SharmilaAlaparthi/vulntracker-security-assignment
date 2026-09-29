import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password,
)
from config import (
    CORS_ALLOWED_ORIGINS,
    NOTIFY_SERVICE_URL,
    SHARE_BASE_URL,
    SHARE_LINK_TTL_HOURS,
)
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)

# CORS is restricted to an explicit allowlist of origins (configured per
# environment). We never reflect an arbitrary Origin back with
# Allow-Credentials: true, which would let any site make authenticated
# cross-site requests on a victim's behalf.
if CORS_ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log the full detail server-side for debugging, but never leak the
    # exception message, type, or stack trace to the client — those can reveal
    # internal paths, SQL, and library versions useful to an attacker.
    logger.exception("Unhandled exception on %s", request.url)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    # Optional password protection for the share link. Bounded length keeps
    # the bcrypt hashing cost predictable and avoids abuse.
    password: Optional[str] = Field(default=None, min_length=1, max_length=128)


class ShareOut(BaseModel):
    share_url: str


class SharedScanOut(BaseModel):
    """Public view of a shared scan. Deliberately omits owner_id and internal
    remediation notes — external stakeholders should only see the finding."""

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime
    expires_at: datetime


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # Never log credentials. Log only the username for audit purposes.
    logger.info("Login attempt for username: %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login for username: %s", payload.username)
        # Generic message so we don't reveal whether the username exists.
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    if len(q) > 100:
        raise HTTPException(status_code=400, detail="Search query too long")
    # Scope the search to the authenticated user's own scans.
    results = search_scans_by_query(db, q, owner_id=current_user.id)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Restrict to the owner's scans to prevent IDOR / broken object-level
    # authorization (a user must not read another user's scan by guessing IDs).
    scan = (
        db.query(models.ScanResult)
        .filter(
            models.ScanResult.id == scan_id,
            models.ScanResult.owner_id == current_user.id,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Shared report links  (Task 1)
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: ShareCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Generate a time-limited, optionally password-protected share link.

    Security notes:
      * Only the scan owner may create a link (ownership check below).
      * The token is 256 bits of CSPRNG entropy (secrets.token_urlsafe(32)),
        making it computationally infeasible to guess.
      * The optional password is stored only as a bcrypt hash.
      * The link expires after SHARE_LINK_TTL_HOURS (24h by default).
    """
    scan = (
        db.query(models.ScanResult)
        .filter(
            models.ScanResult.id == scan_id,
            models.ScanResult.owner_id == current_user.id,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    token = secrets.token_urlsafe(32)
    password_hash = get_password_hash(payload.password) if payload.password else None
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SHARE_LINK_TTL_HOURS)

    link = models.ShareLink(
        token=token,
        scan_id=scan.id,
        created_by=current_user.id,
        password_hash=password_hash,
        expires_at=expires_at,
    )
    db.add(link)
    db.commit()

    share_url = f"{SHARE_BASE_URL.rstrip('/')}/share/{token}"
    return {"share_url": share_url}


@app.get("/share/{token}", response_model=SharedScanOut)
def view_shared_scan(
    token: str,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Public endpoint: return the scan for a valid, unexpired share token.

    We return 404 (not 401/403) for invalid, expired, or revoked tokens so we
    don't confirm the existence of a token to an attacker probing values.
    A wrong/missing password on a protected link returns 401.
    """
    link = db.query(models.ShareLink).filter(models.ShareLink.token == token).first()
    if not link or not link.is_valid():
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    if link.is_password_protected:
        # Constant-time verification via bcrypt. Missing password -> 401.
        if not password or not verify_password(password, link.password_hash):
            raise HTTPException(
                status_code=401, detail="A valid password is required for this link"
            )

    scan = link.scan
    if not scan:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    return SharedScanOut(
        id=scan.id,
        title=scan.title,
        description=scan.description,
        severity=scan.severity,
        status=scan.status,
        cve_id=scan.cve_id,
        affected_component=scan.affected_component,
        created_at=scan.created_at,
        expires_at=link.expires_at,
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}