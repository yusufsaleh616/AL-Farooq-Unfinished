# Al-Farooq

A secure admin login system with **device binding**. An admin signs in from a desktop app, and the server only lets them into the admin dashboard if both the **password** and the **approved PC** check out.

> **Demo project.** It is built to run on one machine (`localhost`). It is not hardened for a production deployment. See [Limitations](#limitations).

## Features

- **Two proofs to log in:** something you know (password) and something you have (a device private key that never leaves the PC).
- **Replay protection:** every login signs a one-time server nonce that expires in 60 seconds.
- **Device approval:** a new PC stays `pending` until a super admin approves it. Devices can be revoked, which ends their sessions at once.
- **Argon2id** password hashing, with timing-safe handling of unknown usernames.
- **Brute-force protection:** account lockout after 5 failures and a per-IP rate limit.
- **Roles (RBAC):** `user`, `admin`, `super_admin`, re-checked in the database on every request.
- **Safe browser hand-off:** a one-time token in the URL fragment, redeemed with a POST for an `HttpOnly`, `SameSite=Strict` session cookie.
- **Audit log** of every security event, visible to super admins.
- Email verification that proves the address only. It never grants admin rights.

## How it works

```
Desktop app                         Server                          Browser
-----------                         ------                          -------
1. request a challenge  ------->    random one-time nonce
2. sign "nonce|fingerprint"
   with the device private key
3. send username, password,
   signature, fingerprint  ----->   checks: nonce, password,
                                    approved device, signature,
                                    fingerprint, role
                                    -> one-time login token (60 s)
4. open  .../login.html#token=...  ---------------------------->  POST /api/web/redeem
                                    token used once -> session      -> admin dashboard
```

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy, SQLite, argon2-cffi, cryptography (Ed25519)
- **Web:** plain HTML, CSS and JavaScript (no inline scripts, strict CSP)
- **Desktop app:** Python, Tkinter, requests

## Quick start

Requires Python 3.10+.

```bash
pip install -r requirements.txt

cd backend
python -m uvicorn app.main:app --port 8000
```

Open <http://localhost:8000> (use `localhost`, not `127.0.0.1`).

### Create the first super admin

1. Register on the website. All fields are required and the password needs 12+ characters.
2. Open the verification link printed in the server console (the demo has no mail server).
3. In a second terminal, from `backend/`:
   ```bash
   python manage.py set-role YOURUSERNAME super_admin
   ```
4. Start the desktop app (`cd desktop_app && python main.py`), enter your credentials and click **Enroll this device**.
5. Approve the device: `python manage.py approve-device 1`
6. Click **Login** in the desktop app. The browser opens on the admin dashboard.

Later devices can be approved from the dashboard by any super admin.

### Console tool

```bash
python manage.py list-users
python manage.py list-devices
python manage.py verify-email USERNAME
python manage.py set-role USERNAME user|admin|super_admin
python manage.py approve-device DEVICE_ID
```

## Tests

```bash
cd backend
python -m pytest
```

34 tests cover signup validation, replay, spoofed fingerprints, lockout, rate limiting, token single use and expiry, session expiry, role changes taking effect immediately, device approval and revocation, and the audit log.

## Project structure

```
backend/        FastAPI app, console tool (manage.py) and tests
web/            register page, token redeem page, admin dashboard
desktop_app/    Tkinter app: device fingerprint, device key, API client
docs/           design sketch and project notes
archive/        earlier iterations, kept for reference only (not safe to reuse)
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ALFAROOQ_PEPPER` | auto-created `backend/.pepper` | Secret for fingerprint HMACs |
| `ALFAROOQ_DB_URL` | `sqlite:///backend/alfarooq.db` | Database |
| `ALFAROOQ_PUBLIC_URL` | `http://localhost:8000` | Address the browser uses |
| `ALFAROOQ_COOKIE_SECURE` | `0` | Set to `1` behind HTTPS |
| `ALFAROOQ_API` | `http://localhost:8000` | Server address for the desktop app |
| `ALFAROOQ_KEY_DIR` | `~/.alfarooq` | Where the desktop app keeps its device key |

Never commit `backend/.pepper` or any `.db` file. The included `.gitignore` already excludes them.

## Limitations

- Runs over plain HTTP on localhost. A real deployment needs HTTPS, PostgreSQL, a real mail sender and a secrets manager.
- The device key is protected by Windows DPAPI, not by hardware (TPM). Fingerprint values (UUID, MAC, serial) can be spoofed, so the private key is the real proof.
- Not implemented: OS biometric unlock (Windows Hello), password reset, phone verification, MFA beyond password plus device.
- Account lockout can be triggered on purpose by someone who knows a username.
- Expired nonces and tokens are not purged from the database.
- The Windows-specific code paths (PowerShell fingerprint, DPAPI) and the Tkinter window were not tested automatically.
