"""Registration, device enrolment and the desktop login flow."""
import hmac
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import config
from .audit import audit
from .database import get_db
from .deps import client_ip, too_many_attempts
from .models import Device, EmailToken, LoginToken, Nonce, User
from .schemas import ChallengeIn, DeviceRequestIn, LoginIn, RegisterIn
from .security import (DUMMY_HASH, fp_hmac, hash_password, is_valid_public_key, new_token,
                       sha256_hex, verify_password, verify_signature)

router = APIRouter()

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")


def send_email(to: str, link: str):
    """Demo version: there is no SMTP server, so we just print the link.
    Swap this for a real mail sender if you ever need one."""
    print(f"\n[demo email to {to}] open this link to verify: {link}\n")


def consume_nonce(db: Session, nonce: str, username: str) -> bool:
    """Mark the nonce as used. Returns False if it is unknown, used or expired.
    It is one UPDATE, so two requests can never both succeed with the same nonce."""
    changed = (
        db.query(Nonce)
        .filter(Nonce.nonce == nonce, Nonce.username == username,
                Nonce.used == False, Nonce.expires_at > time.time())  # noqa: E712
        .update({"used": True}, synchronize_session=False)
    )
    db.commit()
    return changed == 1


# ---------------------------------------------------------------- sign up

@router.post("/api/register", status_code=202)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    username = data.username.strip().lower()
    email = data.email.strip().lower()
    phone = data.phone.strip()

    # every field is required, and we check them here on the server too
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "Username must be 3-32 characters: letters, numbers, . _ -")
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "That email address does not look right")
    if not PHONE_RE.match(phone):
        raise HTTPException(400, "Phone must be 7-15 digits, with an optional leading +")
    if len(data.password) < config.MIN_PASSWORD_LEN:
        raise HTTPException(400, f"Password must be at least {config.MIN_PASSWORD_LEN} characters")
    if data.password != data.confirm_password:
        raise HTTPException(400, "Passwords do not match")

    user = User(username=username, email=email, phone=phone,
                password_hash=hash_password(data.password), role="user")
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # username or email already taken. We give the same answer as for a
        # new account so nobody can use this form to find out who is registered.
        db.rollback()
        return {"status": "check the server console for the verification link"}

    token = new_token()
    db.add(EmailToken(token_hash=sha256_hex(token), user_id=user.id,
                      expires_at=time.time() + config.EMAIL_TOKEN_TTL))
    db.commit()
    send_email(email, f"{config.PUBLIC_URL}/api/verify-email?token={token}")
    audit(db, "register", user.id, client_ip(request))
    return {"status": "check the server console for the verification link"}


@router.get("/api/verify-email", response_class=HTMLResponse)
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    token_hash = sha256_hex(token)
    changed = (
        db.query(EmailToken)
        .filter(EmailToken.token_hash == token_hash, EmailToken.used == False,  # noqa: E712
                EmailToken.expires_at > time.time())
        .update({"used": True}, synchronize_session=False)
    )
    db.commit()
    if changed != 1:
        return HTMLResponse("<h3>This link is invalid or has expired.</h3>", status_code=400)

    row = db.query(EmailToken).filter_by(token_hash=token_hash).first()
    # verifying the email only proves the address is theirs. It does NOT make
    # anyone an admin: the role stays "user" until someone promotes the account.
    db.query(User).filter_by(id=row.user_id).update({"email_verified": True})
    db.commit()
    audit(db, "email_verified", row.user_id, client_ip(request))
    return HTMLResponse("<h3>Email verified. You can close this tab.</h3>")


# ---------------------------------------------------------------- device enrolment

@router.post("/api/device/request")
def device_request(data: DeviceRequestIn, request: Request, db: Session = Depends(get_db)):
    """An admin registers a new PC. It stays 'pending' until a super admin approves it."""
    ip = client_ip(request)
    if too_many_attempts(db, ip):
        raise HTTPException(429, "Too many attempts, try again later")

    username = data.username.strip().lower()
    user = db.query(User).filter_by(username=username).first()
    password_ok = verify_password(data.password, user.password_hash if user else DUMMY_HASH)

    allowed = (password_ok and user is not None and user.email_verified
               and user.role in config.ADMIN_ROLES)
    if not allowed:
        audit(db, "device_request_denied", user.id if user else None, ip)
        raise HTTPException(401, "Invalid credentials")
    if not is_valid_public_key(data.public_key):
        raise HTTPException(400, "Bad public key")

    device = Device(user_id=user.id, public_key=data.public_key, fp_hmac=fp_hmac(data.fp_hash))
    db.add(device)
    db.commit()
    audit(db, "device_requested", user.id, ip, f"device={device.id}")
    return {"device_id": device.id, "status": "pending approval"}


# ---------------------------------------------------------------- login from the desktop app

@router.post("/api/login/challenge")
def login_challenge(data: ChallengeIn, db: Session = Depends(get_db)):
    """Step 1 of login: hand out a random one-time value for the app to sign.
    We hand one out even for usernames that do not exist, so this endpoint
    does not reveal who has an account."""
    nonce = new_token()
    db.add(Nonce(nonce=nonce, username=data.username.strip().lower(),
                 expires_at=time.time() + config.NONCE_TTL))
    db.commit()
    return {"nonce": nonce}


@router.post("/api/login")
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    """Step 2 of login. Needs the right password, an approved device, and a
    fresh signature from that device's private key. If any of that is wrong
    the answer is the same generic 401, so the caller learns nothing."""
    ip = client_ip(request)
    if too_many_attempts(db, ip):
        audit(db, "ip_rate_limited", None, ip)
        raise HTTPException(429, "Too many attempts, try again later")

    username = data.username.strip().lower()
    now = time.time()

    nonce_ok = consume_nonce(db, data.nonce, username)
    user = db.query(User).filter_by(username=username).first()
    locked = bool(user and user.locked_until > now)

    # always run the password check (against a dummy hash if the user is
    # unknown) so the response time does not give away whether the user exists
    password_ok = verify_password(data.password, user.password_hash if user else DUMMY_HASH)
    password_ok = password_ok and user is not None

    device = None
    device_ok = False
    if user:
        device = db.query(Device).filter_by(id=data.device_id, user_id=user.id,
                                            status="approved").first()
        if device:
            signed_ok = verify_signature(device.public_key,
                                         f"{data.nonce}|{data.fp_hash}", data.signature)
            fp_ok = hmac.compare_digest(device.fp_hmac, fp_hmac(data.fp_hash))
            device_ok = signed_ok and fp_ok

    allowed = (nonce_ok and password_ok and device_ok and not locked
               and user.email_verified and user.role in config.ADMIN_ROLES)

    if not allowed:
        if user and not locked:
            user.failed_attempts += 1
            if user.failed_attempts >= config.LOCK_AFTER_FAILS:
                user.locked_until = now + config.LOCK_SECONDS
                user.failed_attempts = 0
                audit(db, "account_locked", user.id, ip)
            db.commit()
        audit(db, "login_failed", user.id if user else None, ip)
        raise HTTPException(401, "Invalid credentials")

    user.failed_attempts = 0
    user.locked_until = 0
    token = new_token()
    db.add(LoginToken(token_hash=sha256_hex(token), user_id=user.id, device_id=device.id,
                      expires_at=now + config.LOGIN_TOKEN_TTL))
    db.commit()
    audit(db, "login_ok", user.id, ip, f"device={device.id}")

    # The token goes after the # so the browser never sends it to the server
    # in a request line, which keeps it out of server logs.
    return {"url": f"{config.PUBLIC_URL}/web/login.html#token={token}"}
