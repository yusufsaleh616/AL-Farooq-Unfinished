"""Shared helpers for the routes: client IP, brute force counters, and the
dependency that protects the admin endpoints (login required + role check)."""
import time

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import config
from .audit import audit
from .database import get_db
from .models import Device, LoginAttempt, User, WebSession
from .security import sha256_hex


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def too_many_attempts(db: Session, ip: str) -> bool:
    """Record this attempt and say whether the IP went over the limit."""
    now = time.time()
    db.query(LoginAttempt).filter(LoginAttempt.ts < now - config.IP_WINDOW).delete()
    db.add(LoginAttempt(ip=ip, ts=now))
    db.commit()
    count = db.query(LoginAttempt).filter(LoginAttempt.ip == ip).count()
    return count > config.IP_MAX_ATTEMPTS


def require_role(*roles: str):
    """Use as Depends(require_role("admin", "super_admin")).

    Everything is checked in the database on every request, so if an admin is
    demoted or their device is revoked, the open session stops working at once.
    """
    def dependency(request: Request, db: Session = Depends(get_db)) -> User:
        token = request.cookies.get(config.SESSION_COOKIE, "")
        now = time.time()

        row = (
            db.query(WebSession, User)
            .join(User, User.id == WebSession.user_id)
            .join(Device, Device.id == WebSession.device_id)
            .filter(
                WebSession.token_hash == sha256_hex(token),
                WebSession.expires_at > now,
                WebSession.created_at > now - config.SESSION_MAX,
                Device.status == "approved",
            )
            .first()
        )
        if row is None or row.User.role not in roles:
            audit(db, "access_denied", row.User.id if row else None,
                  client_ip(request), request.url.path)
            raise HTTPException(status_code=403, detail="Forbidden")

        session, user = row.WebSession, row.User
        # sliding expiry: every request pushes the idle timeout forward,
        # but never past the hard limit
        session.expires_at = min(now + config.SESSION_IDLE, session.created_at + config.SESSION_MAX)
        db.commit()
        return user

    return dependency
