"""Settings for the localhost demo.

Every value can be overridden with an environment variable, but the defaults
are fine for running everything on one machine.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent          # the backend/ folder
WEB_DIR = BASE_DIR.parent / "web"

DATABASE_URL = os.getenv("ALFAROOQ_DB_URL", f"sqlite:///{BASE_DIR / 'alfarooq.db'}")

# Address the browser uses to reach the server. Plain http is OK on localhost only.
PUBLIC_URL = os.getenv("ALFAROOQ_PUBLIC_URL", "http://localhost:8000").rstrip("/")

# The "Secure" cookie flag only works over https, so it is off for the demo.
# Set ALFAROOQ_COOKIE_SECURE=1 if you ever put this behind TLS.
COOKIE_SECURE = os.getenv("ALFAROOQ_COOKIE_SECURE", "0") == "1"
SESSION_COOKIE = "alfarooq_session"


def _load_pepper() -> bytes:
    """Secret used to HMAC the device fingerprints before they hit the database.

    Order: env var first, then a .pepper file next to the backend. If neither
    exists we create the file once, so the demo works out of the box.
    """
    from_env = os.getenv("ALFAROOQ_PEPPER")
    if from_env:
        return from_env.encode()

    pepper_file = BASE_DIR / ".pepper"
    if not pepper_file.exists():
        fd = os.open(pepper_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    return pepper_file.read_text().strip().encode()


PEPPER = _load_pepper()

# Timings, all in seconds
NONCE_TTL = 60               # how long a login challenge is valid
LOGIN_TOKEN_TTL = 60         # how long the desktop -> browser link is valid
EMAIL_TOKEN_TTL = 30 * 60    # email verification link
SESSION_IDLE = 15 * 60       # log out after 15 min without activity
SESSION_MAX = 8 * 3600       # hard limit, even if the admin stays active

# Brute force protection
LOCK_AFTER_FAILS = 5         # wrong attempts before the account locks
LOCK_SECONDS = 15 * 60
IP_WINDOW = 600              # look at the last 10 minutes of attempts per IP
IP_MAX_ATTEMPTS = 30

MIN_PASSWORD_LEN = 12
ADMIN_ROLES = ("admin", "super_admin")
