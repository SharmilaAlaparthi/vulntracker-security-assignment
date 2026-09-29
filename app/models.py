from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanResult", back_populates="owner")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")   # critical | high | medium | low
    status = Column(String(20), default="open")        # open | in_progress | resolved
    cve_id = Column(String(30), nullable=True)
    affected_component = Column(String(200), nullable=False)
    remediation_notes = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    owner = relationship("User", back_populates="scans")
    share_links = relationship(
        "ShareLink", back_populates="scan", cascade="all, delete-orphan"
    )


class ShareLink(Base):
    """A time-limited, optionally password-protected link to one scan result.

    Security properties:
      * `token` is a high-entropy random string (secrets.token_urlsafe) — it is
        the only credential needed to view the scan, so it must be
        unguessable. It is indexed for O(1) lookup.
      * `password_hash` holds a bcrypt hash when the link is password
        protected; the plaintext password is never stored.
      * `expires_at` enforces the 24h (configurable) lifetime.
      * `revoked` allows explicit invalidation before expiry.
    """

    __tablename__ = "share_links"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(64), unique=True, index=True, nullable=False)
    scan_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    password_hash = Column(String(200), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=_utcnow)

    scan = relationship("ScanResult", back_populates="share_links")

    @property
    def is_password_protected(self) -> bool:
        return self.password_hash is not None

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or _utcnow()
        expires = self.expires_at
        # Stored datetimes from SQLite are naive; treat them as UTC.
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now >= expires

    def is_valid(self, now: datetime | None = None) -> bool:
        return not self.revoked and not self.is_expired(now)