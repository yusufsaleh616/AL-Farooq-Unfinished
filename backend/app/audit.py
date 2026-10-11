import time

from sqlalchemy.orm import Session

from .models import AuditLog


def audit(db: Session, event: str, user_id=None, ip=None, detail: str = ""):
    """Write one row to the audit log. Call this for anything security related."""
    db.add(AuditLog(ts=time.time(), event=event, user_id=user_id, ip=ip, detail=detail))
    db.commit()
