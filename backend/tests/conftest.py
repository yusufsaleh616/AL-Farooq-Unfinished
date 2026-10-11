"""Test setup. The environment variables must be set BEFORE the app is imported,
so the tests use a throw-away database and never touch your real one."""
import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="alfarooq_test_")
os.environ["ALFAROOQ_DB_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["ALFAROOQ_PEPPER"] = "test-pepper-not-secret"
os.environ["ALFAROOQ_PUBLIC_URL"] = "http://localhost:8000"

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "desktop_app"))

import pytest                                   # noqa: E402
from fastapi.testclient import TestClient       # noqa: E402

import fingerprint                              # noqa: E402
from app.database import Base, SessionLocal, engine   # noqa: E402
from app.main import app                        # noqa: E402

GOOD_PASSWORD = "CorrectHorse-Battery9"
REAL_FINGERPRINT_HASH = fingerprint.fingerprint_hash   # the autouse fixture below replaces it


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch, tmp_path):
    """Empty database, new device key folder and a fixed fingerprint for each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setenv("ALFAROOQ_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(fingerprint, "fingerprint_hash", lambda: "a" * 64)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


def register(client, username="boss", email="boss@example.com", password=GOOD_PASSWORD, **extra):
    body = {"username": username, "email": email, "phone": "+971501234567",
            "password": password, "confirm_password": password}
    body.update(extra)
    return client.post("/api/register", json=body)


@pytest.fixture
def make_admin(client, db):
    """Registers a user and promotes them, like manage.py would do."""
    from app.models import User

    def _make(username="boss", role="super_admin"):
        register(client, username=username, email=f"{username}@example.com")
        user = db.query(User).filter_by(username=username).first()
        user.email_verified = True
        user.role = role
        db.commit()
        return user
    return _make
