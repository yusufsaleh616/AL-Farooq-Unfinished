"""The browser side of login: swap the one-time token for a session cookie."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from . import config
from .audit import audit
from .database import get_db
from .deps import client_ip
from .models import Device, LoginToken, User, WebSession
from .schemas import RedeemIn
from .security import new_token, sha256_hex

router = APIRouter()


@router.post("/api/web/redeem")
def redeem(data: RedeemIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    token_hash = sha256_hex(data.token)
    now = time.time()

    # single UPDATE: the token can be used once, and only before it expires
    changed = (
        db.query(LoginToken)
        .filter(LoginToken.token_hash == token_hash, LoginToken.used == False,  # noqa: E712
                LoginToken.expires_at > now)
        .update({"used": True}, synchronize_session=False)
    )
    db.commit()
    if changed != 1:
        audit(db, "redeem_failed", None, ip)
        raise HTTPException(403, "Invalid or expired link")

    login_token = db.query(LoginToken).filter_by(token_hash=token_hash).first()
    user = db.query(User).filter_by(id=login_token.user_id).first()
    device = db.query(Device).filter_by(id=login_token.device_id).first()

    # things may have changed in the last minute, so check again
    if (user is None or user.role not in config.ADMIN_ROLES
            or device is None or device.status != "approved"):
        audit(db, "redeem_failed", login_token.user_id, ip, "role or device changed")
        raise HTTPException(403, "Invalid or expired link")

    session_token = new_token()
    db.add(WebSession(token_hash=sha256_hex(session_token), user_id=user.id, device_id=device.id,
                      created_at=now, expires_at=now + config.SESSION_IDLE))
    db.commit()
    audit(db, "session_started", user.id, ip, f"device={device.id}")

    response.set_cookie(config.SESSION_COOKIE, session_token, max_age=config.SESSION_IDLE,
                        httponly=True, samesite="strict", secure=config.COOKIE_SECURE)
    return {"ok": True}
