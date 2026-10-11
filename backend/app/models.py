import time

from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)   # stored lowercase
    email = Column(String, unique=True, nullable=False)      # stored lowercase
    phone = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)           # Argon2id, never the password
    role = Column(String, nullable=False, default="user")    # user | admin | super_admin
    email_verified = Column(Boolean, nullable=False, default=False)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(Float, nullable=False, default=0)
    created_at = Column(Float, nullable=False, default=time.time)


class Device(Base):
    """A PC that an admin wants to log in from. Needs approval before it works."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    public_key = Column(String, nullable=False)    # Ed25519 public key (base64)
    fp_hmac = Column(String, nullable=False)       # HMAC of the fingerprint hash, not the raw values
    status = Column(String, nullable=False, default="pending")   # pending | approved | revoked
    approved_by = Column(Integer, nullable=True)
    created_at = Column(Float, nullable=False, default=time.time)


class EmailToken(Base):
    __tablename__ = "email_tokens"

    token_hash = Column(String, primary_key=True)  # we only keep the hash of the token
    user_id = Column(Integer, nullable=False)
    expires_at = Column(Float, nullable=False)
    used = Column(Boolean, nullable=False, default=False)


class Nonce(Base):
    """One-time challenge the desktop app has to sign when logging in."""
    __tablename__ = "nonces"

    nonce = Column(String, primary_key=True)
    username = Column(String, nullable=False)
    expires_at = Column(Float, nullable=False)
    used = Column(Boolean, nullable=False, default=False)


class LoginToken(Base):
    """The one-time token inside the link the desktop app opens in the browser."""
    __tablename__ = "login_tokens"

    token_hash = Column(String, primary_key=True)
    user_id = Column(Integer, nullable=False)
    device_id = Column(Integer, nullable=False)
    expires_at = Column(Float, nullable=False)
    used = Column(Boolean, nullable=False, default=False)


class WebSession(Base):
    __tablename__ = "web_sessions"

    token_hash = Column(String, primary_key=True)
    user_id = Column(Integer, nullable=False)
    device_id = Column(Integer, nullable=False)
    created_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True)
    ip = Column(String, nullable=False, index=True)
    ts = Column(Float, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    ts = Column(Float, nullable=False, default=time.time)
    event = Column(String, nullable=False)
    user_id = Column(Integer, nullable=True)
    ip = Column(String, nullable=True)
    detail = Column(String, nullable=True)
