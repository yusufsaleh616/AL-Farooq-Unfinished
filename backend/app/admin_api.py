"""Endpoints that need a logged-in admin."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from . import config
from .audit import audit
from .database import get_db
from .deps import client_ip, require_role
from .models import AuditLog, Device, LoginToken, User, WebSession
from .security import sha256_hex

router = APIRouter()

any_admin = require_role(*config.ADMIN_ROLES)
super_admin_only = require_role("super_admin")


@router.get("/api/admin/dashboard")
def dashboard(user: User = Depends(any_admin)):
    return {"message": "Welcome to Admin Panel", "username": user.username, "role": user.role}


@router.post("/api/logout")
def logout(request: Request, response: Response, user: User = Depends(any_admin),
           db: Session = Depends(get_db)):
    token = request.cookies.get(config.SESSION_COOKIE, "")
    db.query(WebSession).filter_by(token_hash=sha256_hex(token)).delete()
    db.commit()
    audit(db, "logout", user.id, client_ip(request))
    response.delete_cookie(config.SESSION_COOKIE)
    return {"ok": True}


@router.get("/api/admin/devices")
def list_devices(user: User = Depends(super_admin_only), db: Session = Depends(get_db)):
    rows = (db.query(Device, User).join(User, User.id == Device.user_id)
            .order_by(Device.id.desc()).all())
    return [{"id": d.id, "username": u.username, "status": d.status, "created_at": d.created_at}
            for d, u in rows]


@router.post("/api/admin/devices/{device_id}/{action}")
def decide_device(device_id: int, action: str, request: Request,
                  user: User = Depends(super_admin_only), db: Session = Depends(get_db)):
    if action not in ("approve", "revoke"):
        raise HTTPException(404, "Not found")
    device = db.query(Device).filter_by(id=device_id).first()
    if device is None:
        raise HTTPException(404, "Not found")

    if action == "approve":
        if device.status != "pending":
            raise HTTPException(409, "Only pending devices can be approved")
        device.status = "approved"
        device.approved_by = user.id
    else:
        device.status = "revoked"
        # kick out anyone already logged in from this device
        db.query(WebSession).filter_by(device_id=device.id).delete()
        db.query(LoginToken).filter_by(device_id=device.id).delete()
    db.commit()
    audit(db, f"device_{device.status}", user.id, client_ip(request), f"device={device.id}")
    return {"id": device.id, "status": device.status}


@router.get("/api/admin/audit")
def audit_log(user: User = Depends(super_admin_only), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
    return [{"ts": r.ts, "event": r.event, "user_id": r.user_id, "ip": r.ip, "detail": r.detail}
            for r in rows]
