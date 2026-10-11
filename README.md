# Al-Farooq (localhost demo) (Unfinished)

A demo of a secure admin login system. An admin logs in from a **desktop app**;
the server checks the password **and** that the request comes from an **approved
PC**; if both are right, the browser is opened on the **admin dashboard**.

> This is a demo that runs on one machine (`localhost`). It is not hardened for
> a real company deployment. See "What is different from production" below.

---

## 1. How it works

```
 Desktop app (admin PC)                 Server (FastAPI + SQLite)            Browser
 ----------------------                 -------------------------            -------
 1. ask for a challenge  ------------>  make a random one-time nonce
 2. sign "nonce|fingerprint" with
    the device private key
 3. send username + password +
    signature + fingerprint hash ---->  check, all must pass:
                                          - nonce unused and < 60 s old
                                          - password (Argon2id)
                                          - device is approved
                                          - signature matches the device public key
                                          - fingerprint matches
                                          - role is admin / super_admin
                                        create a one-time login token (60 s)
 4. open URL .../login.html#token=... ----------------------------------->  page reads the token
                                        <------------------------------  POST /api/web/redeem
                                        token used once -> session cookie
                                                                            redirect to dashboard
```

Why two proofs: the password is something the admin **knows**, the device private
key is something the admin **has**. Stealing only one of them is not enough.

---

## 2. Quick start

Needs Python 3.10+.

```bash
pip install -r requirements.txt

cd backend
python -m uvicorn app.main:app --port 8000
```

Open <http://localhost:8000> (use `localhost`, not `127.0.0.1`, see Troubleshooting).

### Creating the first super admin

The first admin cannot approve their own device through the website (nobody can
log in yet), so the first steps use a console tool on the server machine.

1. Open <http://localhost:8000> and register (all fields are required).
2. The server console prints a verification link (there is no mail server in the
   demo). Open it.
3. In a second terminal, from `backend/`:
   ```bash
   python manage.py set-role YOURUSERNAME super_admin
   ```
4. Start the desktop app: `cd desktop_app && python main.py`.
   Enter username + password and click **Enroll this device**. A popup shows the device ID.
5. Approve it: `python manage.py approve-device 1` (use the ID from the popup).
6. Click **Login** in the desktop app. The browser opens on the admin dashboard.

After that, new admins register, verify their email, get promoted with
`manage.py set-role NAME admin`, enroll from their PC, and a super admin approves
the device from the dashboard (Devices table).

### Other commands

```bash
python manage.py list-users
python manage.py list-devices
python manage.py verify-email USERNAME      # skip the email link
python -m pytest                            # run the tests (from backend/)
```

---

## 3. Project layout

```
AlFarooq/
  backend/
    app/
      config.py       settings, timings, secret ("pepper") loading
      database.py     SQLAlchemy engine and session
      models.py       tables: users, devices, nonces, tokens, sessions, audit_log ...
      security.py     Argon2id, token hashing, signature check
      schemas.py      request bodies (with length limits)
      deps.py         IP rate limit + the login/role check for protected routes
      auth_api.py     register, verify email, enroll device, challenge, login
      web_auth.py     browser side: redeem the one-time token for a session
      admin_api.py    dashboard, logout, device approve/revoke, audit log
      audit.py        writes security events
      main.py         app setup, security headers, serves /web
    manage.py         console admin tool
    tests/            34 automated tests
  web/                register page, token redeem page, dashboard (HTML/JS/CSS)
  desktop_app/        Tkinter app: fingerprint, device key, API client, UI
  docs/               your notes, your drawbacks files, your sketch
  archive/            your old iterations (secrets removed, see archive/README.md)
  requirements.txt
```



## 4. The security fixes in detail

These cover the 8 risks from my earlier review, plus the extras.

1. **Device fingerprint can be faked.** MAC/UUID/serial are hashed on the PC, and the
   server stores only an HMAC of that hash. More importantly, the proof of "this is the
   approved PC" is the **private key**, stored only on that PC (Windows DPAPI-encrypted).
   Knowing the fingerprint without the key fails (tested).
2. **Replay.** Every login uses a server nonce: random, single use, 60 s. The signature
   covers `nonce|fingerprint`. Re-sending a captured login request fails (tested).
3. **Password storage.** Argon2id with automatic salt. A wrong username takes about as
   long as a wrong password (dummy hash), so timing does not reveal which usernames exist.
4. **Brute force.** Account locks for 15 min after 5 failures. Each IP is limited to
   30 attempts per 10 min (HTTP 429). Correct password during a lock is still refused.
5. **New or replaced device.** Enrolment creates a `pending` device. A super admin approves
   or revokes it from the dashboard. Revoking also deletes that device's sessions and tokens.
6. **Sessions.** Random token, only its hash is stored. `HttpOnly` + `SameSite=Strict`
   cookie. 15 min idle timeout and an 8 h hard limit. Logout deletes the session.
7. **Audit log.** Registration, email verification, device requests/approvals/revocations,
   login success/failure, lockouts, rate limiting, token redeems, access denied, logout.
   Super admins see the latest 100 in the dashboard.
8. **Roles (RBAC).** Roles are `user`, `admin`, `super_admin`. The role, the session and the
   device status are re-read from the database on **every** request. Demoting a user or
   revoking a device ends the open session immediately (tested, including direct DB edits).

Extras:

- **Email verification does not make anyone an admin.** Signing up always gives role `user`.
  Promotion is done by a person from the console (this fixes the issue of "click the link = admin").
- **Verification links**: random, only the hash is stored, 30 min, single use.
- **Same answer for every login failure** (`Invalid credentials`), and for duplicate signups.
- **Server-side validation** for every signup field (all required): username, email, phone,
  12+ character password, matching confirmation.
- **Cross-site request check**: POSTs with a foreign `Origin` header are refused.
- **Security headers**: `X-Frame-Options: DENY`, `nosniff`, `Cache-Control: no-store`, and a
  Content-Security-Policy on the web pages (no inline scripts or styles).
- **No `innerHTML`** in the dashboard JavaScript, so database content cannot inject HTML.
- **Atomic one-time use**: nonces and tokens are consumed with a single `UPDATE`, so two
  parallel requests cannot both succeed.
- **Queries are parameterized** (SQLAlchemy), which is the main defence against SQL injection.

---

## 5. Testing

**34 automated tests** (`cd backend && python -m pytest`), all passing. They cover:
signup validation and duplicate handling, Argon2id storage, email-link single use,
normal users blocked from enrolling devices, pending device refused, full happy path,
replay, expired nonce, fingerprint spoofing without the key, right key with wrong fingerprint,
wrong password vs unknown user (identical answers), malformed body, lockout, IP rate limit,
token single use and expiry, only hashes stored, idle expiry, logout, cross-site POST,
admin vs super admin, demotion taking effect at once, device approve/revoke, revoked-device
sessions, audit entries, and fingerprint stability.

**Mutation check.** I deliberately broke the code five ways in a scratch copy
(nonce never marked used, signature check removed, role check removed, device status
ignored, password check always true). Four were caught at once. The fifth (device status
ignored per request) was **not** caught, so I added a test for it. Now all five are caught.

**Live run.** Started the real server, used the real desktop client over HTTP, curl as the
browser: register, verify, promote, enroll, refused before approval, approve, login,
redeem, reused token refused, dashboard, devices, audit, evil-origin POST blocked,
logout, dashboard refused afterwards. No server errors.

**A bug the live run found.** On a PC without a readable MAC address, Python's
`uuid.getnode()` returns a random value on every run, so the fingerprint changed each time
and login failed. Fixed in `fingerprint.py` (fake MACs are ignored; if no hardware
identifier can be read at all, the app refuses instead of using an empty fingerprint).
Four regression tests were added.

---

## 6. What is different from production

This is a localhost demo, so I kept these simple on purpose:

| Demo choice | For a real deployment |
|---|---|
| Plain `http://localhost`, cookie `Secure` flag off | Put it behind HTTPS (nginx etc.), set `ALFAROOQ_COOKIE_SECURE=1` and a real `ALFAROOQ_PUBLIC_URL` |
| SQLite file | PostgreSQL |
| Email link printed in the server console | Real SMTP |
| Pepper in an auto-created `.pepper` file | A secrets manager / env variable |
| First admin created via console | Same, or an install script |
| IP taken from the direct connection | Behind a proxy, configure trusted proxy headers |
| Device key stored with DPAPI (not hardware-bound) | TPM-backed key |

---

## 7. Known limitations / not done

- **Fingerprint login with the OS biometric** (Windows Hello / Secure Enclave) from your
  original notes is **not implemented**. It is an OS feature that would be added around the app.
- **No password reset**, **no phone verification (OTP)**, **no MFA** beyond password + device.
- **No real email sending.**
- **Promoting a user to admin** is console-only (`manage.py set-role`), by design.
- **Lockout can be abused**: someone who knows an admin username can lock that account by
  failing logins on purpose (the usual lockout trade-off). Replayed requests also count as failures.
- **Expired nonces, tokens and old attempts are not purged** from the database. Fine for a demo,
  would need a cleanup job in production.
- **If you delete `backend/.pepper`** (or change `ALFAROOQ_PEPPER`), stored fingerprints no longer
  match and every device must be enrolled again.
- The device key is software-protected. Someone with access to the admin's Windows account
  could use it.
- The 15 min idle / 8 h limits and 5-failure lockout are my choices. Change them in `config.py`.

## 8. API reference

| Method | Path | Who | What |
|---|---|---|---|
| POST | `/api/register` | anyone | Create a `user` account |
| GET | `/api/verify-email?token=` | anyone with the link | Verify the email (no role change) |
| POST | `/api/device/request` | admin by password | Enroll a PC (becomes `pending`) |
| POST | `/api/login/challenge` | anyone | Get a one-time nonce |
| POST | `/api/login` | desktop app | Password + signature, returns the browser URL |
| POST | `/api/web/redeem` | browser | Swap the one-time token for the session cookie |
| GET | `/api/admin/dashboard` | admin, super admin | Welcome + who you are |
| POST | `/api/logout` | admin, super admin | End the session |
| GET | `/api/admin/devices` | super admin | List devices |
| POST | `/api/admin/devices/{id}/approve` or `revoke` | super admin | Decide a device |
| GET | `/api/admin/audit` | super admin | Latest 100 security events |

Interactive docs are at <http://localhost:8000/docs> while the server runs.

## 9. Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `ALFAROOQ_PEPPER` | auto file `backend/.pepper` | Secret for fingerprint HMACs |
| `ALFAROOQ_DB_URL` | `sqlite:///backend/alfarooq.db` | Database |
| `ALFAROOQ_PUBLIC_URL` | `http://localhost:8000` | Address the browser uses (also the allowed Origin) |
| `ALFAROOQ_COOKIE_SECURE` | `0` | Set `1` behind HTTPS |
| `ALFAROOQ_API` | `http://localhost:8000` | Where the desktop app finds the server |
| `ALFAROOQ_KEY_DIR` | `~/.alfarooq` | Where the desktop app keeps its device key |

Timings and limits (nonce 60 s, token 60 s, idle 15 min, lock 5 fails / 15 min ...) are at the top of
`backend/app/config.py`.

---

## 10. Troubleshooting

- **"Cross-site request blocked" in the browser**: you opened the site as `127.0.0.1`. Use
  `http://localhost:8000`, or set `ALFAROOQ_PUBLIC_URL` to the address you use.
- **"Invalid credentials" and you are sure the password is right**: the device may still be
  pending (approve it), the account may be locked (wait 15 min), the role may still be `user`,
  the email may be unverified, or `.pepper` was deleted (enroll again). The server never says which,
  on purpose; check `python manage.py list-users` / `list-devices` and the audit log.
- **"This PC is not enrolled yet"**: click *Enroll this device* first.
- **Login link says invalid or expired**: it lives 60 seconds and works once. Log in again.
- **Desktop app cannot reach the server**: start the server first, or set `ALFAROOQ_API`.
- **`ModuleNotFoundError: app`**: run `uvicorn` and `manage.py` from inside `backend/`.
- **Start fresh**: stop the server and delete `backend/alfarooq.db` (and `~/.alfarooq` on the admin PC).
