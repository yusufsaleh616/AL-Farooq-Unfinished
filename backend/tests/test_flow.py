import base64
import time

import api_client
import device_key
from app.models import (AuditLog, Device, LoginAttempt, LoginToken, Nonce, User, WebSession)
from tests.conftest import GOOD_PASSWORD, register
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def enroll_and_approve(client, db, username="boss"):
    device_id = api_client.enroll_device(username, GOOD_PASSWORD, http=client)
    device = db.query(Device).filter_by(id=device_id).first()
    device.status = "approved"
    db.commit()
    return device_id


def token_from(url: str) -> str:
    return url.split("#token=")[1]


def full_login(client, username="boss"):
    url = api_client.login(username, GOOD_PASSWORD, http=client)
    return client.post("/api/web/redeem", json={"token": token_from(url)})


# ---------------------------------------------------------------- registration

def test_signup_creates_plain_user(client, db):
    assert register(client).status_code == 202
    assert db.query(User).one().role == "user"


def test_signup_validation(client):
    assert register(client, password="short").status_code == 400
    assert register(client, confirm_password="different-password-1").status_code == 400
    assert register(client, email="not-an-email").status_code == 400
    assert register(client, phone="abc").status_code == 400
    assert register(client, username="x").status_code == 400


def test_signup_missing_field_rejected(client):
    body = {"username": "boss", "email": "a@b.co", "password": GOOD_PASSWORD,
            "confirm_password": GOOD_PASSWORD}                       # no phone
    assert client.post("/api/register", json=body).status_code == 422


def test_duplicate_signup_looks_identical(client):
    first = register(client)
    again = register(client)
    assert (first.status_code, first.json()) == (again.status_code, again.json())


def test_password_is_argon2_not_plain(client, db):
    register(client)
    stored = db.query(User).one().password_hash
    assert stored.startswith("$argon2id$") and GOOD_PASSWORD not in stored


def test_email_link_verifies_but_grants_no_admin(client, db, capfd):
    register(client)
    link = [l for l in capfd.readouterr().out.splitlines() if "verify-email" in l][0]
    token = link.split("token=")[1].strip()
    assert client.get(f"/api/verify-email?token={token}").status_code == 200
    user = db.query(User).one()
    assert user.email_verified is True and user.role == "user"
    assert client.get(f"/api/verify-email?token={token}").status_code == 400    # single use


# ---------------------------------------------------------------- enrolment and login

def test_normal_user_cannot_enroll_a_device(client, db):
    register(client)
    db.query(User).update({"email_verified": True})
    db.commit()
    try:
        api_client.enroll_device("boss", GOOD_PASSWORD, http=client)
        assert False, "should have been refused"
    except api_client.ApiError as exc:
        assert str(exc) == "Invalid credentials"


def test_pending_device_cannot_log_in(client, db, make_admin):
    make_admin()
    api_client.enroll_device("boss", GOOD_PASSWORD, http=client)
    try:
        api_client.login("boss", GOOD_PASSWORD, http=client)
        assert False, "pending device must be refused"
    except api_client.ApiError as exc:
        assert str(exc) == "Invalid credentials"


def test_happy_path_end_to_end(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    url = api_client.login("boss", GOOD_PASSWORD, http=client)
    assert "#token=" in url and "?token=" not in url        # token stays out of the request line

    redeemed = client.post("/api/web/redeem", json={"token": token_from(url)})
    assert redeemed.status_code == 200
    cookie = redeemed.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie

    dash = client.get("/api/admin/dashboard")
    assert dash.status_code == 200 and dash.json()["message"] == "Welcome to Admin Panel"


def test_login_replay_is_rejected(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    payload = api_client.build_login_payload("boss", GOOD_PASSWORD, http=client)
    assert client.post("/api/login", json=payload).status_code == 200
    assert client.post("/api/login", json=payload).status_code == 401      # exact same request again


def test_expired_nonce_is_rejected(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    payload = api_client.build_login_payload("boss", GOOD_PASSWORD, http=client)
    db.query(Nonce).update({"expires_at": time.time() - 1})
    db.commit()
    assert client.post("/api/login", json=payload).status_code == 401


def test_spoofed_fingerprint_without_private_key_fails(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    payload = api_client.build_login_payload("boss", GOOD_PASSWORD, http=client)
    attacker = Ed25519PrivateKey.generate()                  # knows the fingerprint, not the key
    msg = f"{payload['nonce']}|{payload['fp_hash']}".encode()
    payload["signature"] = base64.b64encode(attacker.sign(msg)).decode()
    assert client.post("/api/login", json=payload).status_code == 401


def test_right_key_wrong_fingerprint_fails(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    payload = api_client.build_login_payload("boss", GOOD_PASSWORD, http=client)
    payload["fp_hash"] = "b" * 64
    payload["signature"] = device_key.sign(device_key.load_or_create_key(),
                                           f"{payload['nonce']}|{payload['fp_hash']}")
    assert client.post("/api/login", json=payload).status_code == 401


def test_wrong_password_and_unknown_user_look_the_same(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    wrong_pw = api_client.build_login_payload("boss", "WrongPassword-123", http=client)
    unknown = dict(api_client.build_login_payload("boss", GOOD_PASSWORD, http=client),
                   username="nobody")
    a, b = client.post("/api/login", json=wrong_pw), client.post("/api/login", json=unknown)
    assert (a.status_code, a.json()) == (b.status_code, b.json()) == (401, {"detail": "Invalid credentials"})


def test_malformed_login_body_is_a_422_not_a_crash(client):
    assert client.post("/api/login", json={"username": "x"}).status_code == 422


def test_account_locks_after_repeated_failures(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    for _ in range(5):
        bad = api_client.build_login_payload("boss", "WrongPassword-123", http=client)
        assert client.post("/api/login", json=bad).status_code == 401
    good = api_client.build_login_payload("boss", GOOD_PASSWORD, http=client)
    assert client.post("/api/login", json=good).status_code == 401           # locked, even with the right password
    assert any(e.event == "account_locked" for e in db.query(AuditLog))


def test_ip_rate_limit(client, db):
    db.add_all([LoginAttempt(ip="testclient", ts=time.time()) for _ in range(31)])
    db.commit()
    res = client.post("/api/login", json={"username": "a", "password": "b", "device_id": 1,
                                          "nonce": "n", "fp_hash": "f", "signature": "s"})
    assert res.status_code == 429


# ---------------------------------------------------------------- browser token and sessions

def test_login_token_is_single_use(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    token = token_from(api_client.login("boss", GOOD_PASSWORD, http=client))
    assert client.post("/api/web/redeem", json={"token": token}).status_code == 200
    assert client.post("/api/web/redeem", json={"token": token}).status_code == 403


def test_login_token_expires(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    token = token_from(api_client.login("boss", GOOD_PASSWORD, http=client))
    db.query(LoginToken).update({"expires_at": time.time() - 1})
    db.commit()
    assert client.post("/api/web/redeem", json={"token": token}).status_code == 403


def test_only_hashes_are_stored(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    token = token_from(api_client.login("boss", GOOD_PASSWORD, http=client))
    client.post("/api/web/redeem", json={"token": token})
    session_cookie = client.cookies.get("alfarooq_session")
    assert db.query(LoginToken).one().token_hash != token
    assert db.query(WebSession).one().token_hash != session_cookie


def test_no_session_means_no_dashboard(client):
    assert client.get("/api/admin/dashboard").status_code == 403


def test_idle_session_expires(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    full_login(client)
    db.query(WebSession).update({"expires_at": time.time() - 1})
    db.commit()
    assert client.get("/api/admin/dashboard").status_code == 403


def test_logout_kills_the_session(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    full_login(client)
    assert client.post("/api/logout", json={}).status_code == 200
    assert client.get("/api/admin/dashboard").status_code == 403


def test_cross_site_post_is_blocked(client):
    res = client.post("/api/register", json={}, headers={"Origin": "http://evil.example"})
    assert res.status_code == 403


# ---------------------------------------------------------------- roles and devices

def test_plain_admin_cannot_manage_devices(client, db, make_admin):
    make_admin("boss", "admin")
    enroll_and_approve(client, db)
    full_login(client)
    assert client.get("/api/admin/dashboard").status_code == 200
    assert client.get("/api/admin/devices").status_code == 403
    assert client.get("/api/admin/audit").status_code == 403
    assert client.post("/api/admin/devices/1/approve", json={}).status_code == 403


def test_demotion_applies_to_the_open_session_immediately(client, db, make_admin):
    user = make_admin()
    enroll_and_approve(client, db)
    full_login(client)
    assert client.get("/api/admin/dashboard").status_code == 200
    user.role = "user"
    db.commit()
    assert client.get("/api/admin/dashboard").status_code == 403


def test_super_admin_can_approve_and_revoke(client, db, make_admin):
    make_admin("boss", "super_admin")
    enroll_and_approve(client, db, "boss")
    full_login(client)

    # a second admin asks to enrol another PC
    make_admin("second", "admin")
    second_device = Device(user_id=db.query(User).filter_by(username="second").one().id,
                            public_key="x", fp_hmac="y")
    db.add(second_device)
    db.commit()
    assert client.get("/api/admin/devices").json()[0]["status"] == "pending"
    assert client.post(f"/api/admin/devices/{second_device.id}/approve", json={}).json()["status"] == "approved"
    assert client.post(f"/api/admin/devices/{second_device.id}/approve", json={}).status_code == 409
    assert client.post(f"/api/admin/devices/{second_device.id}/revoke", json={}).json()["status"] == "revoked"
    assert client.post("/api/admin/devices/1/explode", json={}).status_code == 404


def test_revoking_a_device_ends_its_sessions(client, db, make_admin):
    make_admin("boss", "super_admin")
    device_id = enroll_and_approve(client, db)
    full_login(client)
    assert client.post(f"/api/admin/devices/{device_id}/revoke", json={}).status_code == 200
    assert client.get("/api/admin/dashboard").status_code == 403


def test_audit_log_records_the_important_events(client, db, make_admin):
    make_admin()
    enroll_and_approve(client, db)
    full_login(client)
    client.get("/api/admin/dashboard")
    events = {e.event for e in db.query(AuditLog)}
    assert {"register", "device_requested", "login_ok", "session_started"} <= events


def test_device_revoked_behind_the_apis_back_still_blocks_the_session(client, db, make_admin):
    # e.g. someone edits the database directly: the open session must stop working anyway
    make_admin("boss", "super_admin")
    device_id = enroll_and_approve(client, db)
    full_login(client)
    assert client.get("/api/admin/dashboard").status_code == 200
    db.query(Device).filter_by(id=device_id).update({"status": "revoked"})
    db.commit()
    assert client.get("/api/admin/dashboard").status_code == 403
