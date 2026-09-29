import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["title"] == "SQL Injection via login"


def test_search_no_match_returns_empty():
    token = register_and_login()
    client.post("/scans", json={
        "title": "XSS finding",
        "severity": "high",
        "affected_component": "web",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=nonexistentterm", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_search_is_sql_injection_safe():
    # A classic injection payload must be treated as a literal search string,
    # returning no rows rather than dumping the table or erroring.
    token = register_and_login()
    client.post("/scans", json={
        "title": "Benign finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get(
        "/scans/search?q=' OR '1'='1", headers=auth_headers(token)
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_search_is_scoped_to_owner():
    token_a = register_and_login("usera", "usera@example.com", "pw")
    client.post("/scans", json={
        "title": "UserA secret finding",
        "severity": "high",
        "affected_component": "web",
    }, headers=auth_headers(token_a))
    token_b = register_and_login("userb", "userb@example.com", "pw")
    resp = client.get("/scans/search?q=secret", headers=auth_headers(token_b))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Authorization / IDOR
# ---------------------------------------------------------------------------

def test_get_scan_requires_auth():
    resp = client.get("/scans/1")
    assert resp.status_code in (401, 403)


def test_cannot_read_another_users_scan_by_id():
    token_a = register_and_login("owner", "owner@example.com", "pw")
    scan_id = client.post("/scans", json={
        "title": "Private finding",
        "severity": "high",
        "affected_component": "web",
    }, headers=auth_headers(token_a)).json()["id"]

    token_b = register_and_login("intruder", "intruder@example.com", "pw")
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(token_b))
    # Must not leak another user's scan — 404 (not found for this user).
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# JWT hardening — the unsigned "none" algorithm must be rejected
# ---------------------------------------------------------------------------

def test_alg_none_token_is_rejected():
    # Hand-craft an unsigned JWT the way an attacker would (alg=none, empty
    # signature). Our decode_token must reject it because "none" is not in the
    # allowed algorithms list.
    import base64
    import json

    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64({"sub": "alice"})
    forged = f"{header}.{payload}."  # empty signature

    resp = client.get("/scans", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Error handling — no internal detail leakage
# ---------------------------------------------------------------------------

def test_error_response_has_no_traceback():
    # Trigger auth failure and confirm no stack trace / internal fields leak.
    resp = client.get("/scans", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401
    assert "traceback" not in resp.json()


# ---------------------------------------------------------------------------
# Task 1 — Shared report links
# ---------------------------------------------------------------------------

def _create_scan(token, title="Shareable finding"):
    return client.post("/scans", json={
        "title": title,
        "severity": "high",
        "affected_component": "web",
    }, headers=auth_headers(token)).json()["id"]


def test_share_requires_auth():
    resp = client.post("/scans/1/share", json={})
    assert resp.status_code in (401, 403)


def test_share_and_view_without_password():
    token = register_and_login()
    scan_id = _create_scan(token)
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 201
    share_url = resp.json()["share_url"]
    assert "/share/" in share_url

    token_str = share_url.rsplit("/share/", 1)[1]
    view = client.get(f"/share/{token_str}")
    assert view.status_code == 200
    body = view.json()
    assert body["id"] == scan_id
    # Public view must not leak owner_id or remediation_notes.
    assert "owner_id" not in body
    assert "remediation_notes" not in body


def test_share_cannot_share_other_users_scan():
    token_a = register_and_login("a", "a@example.com", "pw")
    scan_id = _create_scan(token_a)
    token_b = register_and_login("b", "b@example.com", "pw")
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token_b))
    assert resp.status_code == 404


def test_share_with_password_requires_password():
    token = register_and_login()
    scan_id = _create_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "s3cret-pass"},
        headers=auth_headers(token),
    ).json()["share_url"]
    token_str = share_url.rsplit("/share/", 1)[1]

    # No password -> 401
    assert client.get(f"/share/{token_str}").status_code == 401
    # Wrong password -> 401
    assert client.get(f"/share/{token_str}?password=wrong").status_code == 401
    # Correct password -> 200
    ok = client.get(f"/share/{token_str}?password=s3cret-pass")
    assert ok.status_code == 200
    assert ok.json()["id"] == scan_id


def test_share_invalid_token_returns_404():
    resp = client.get("/share/this-token-does-not-exist")
    assert resp.status_code == 404


def test_share_expired_token_returns_404():
    from datetime import datetime, timedelta, timezone

    import models

    token = register_and_login()
    scan_id = _create_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share", json={}, headers=auth_headers(token)
    ).json()["share_url"]
    token_str = share_url.rsplit("/share/", 1)[1]

    # Force expiry in the DB.
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).filter(models.ShareLink.token == token_str).first()
        link.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/share/{token_str}")
    assert resp.status_code == 404
