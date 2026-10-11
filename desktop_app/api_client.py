"""Talks to the Al-Farooq server. No GUI code in here, so it is easy to test.

Pass your own `http` object in tests (for example FastAPI's TestClient). When
it is left out we use a normal requests session.
"""
import os

import requests

import device_key
import fingerprint

API = os.getenv("ALFAROOQ_API", "http://localhost:8000").rstrip("/")


class ApiError(Exception):
    """Something went wrong. The message is safe to show to the user."""


def _connection(http, base):
    if http is None:
        return requests.Session(), API
    return http, (base if base is not None else "")


def _post(http, base, path, payload):
    try:
        res = http.post(f"{base}{path}", json=payload, timeout=10) if base else \
              http.post(path, json=payload)
    except requests.RequestException as exc:
        raise ApiError(f"Could not reach the server: {exc}") from exc
    return res


def _error_text(res) -> str:
    if res.status_code == 401:
        return "Invalid credentials"
    if res.status_code == 429:
        return "Too many attempts. Wait a few minutes and try again."
    try:
        detail = res.json().get("detail")
        if isinstance(detail, str):
            return detail
    except ValueError:
        pass
    return f"Server returned an error ({res.status_code})"


def enroll_device(username: str, password: str, http=None, base=None) -> int:
    """Run once per PC. The server keeps the device as 'pending' until a super
    admin approves it, so login will not work right away."""
    http, base = _connection(http, base)
    key = device_key.load_or_create_key()
    res = _post(http, base, "/api/device/request", {
        "username": username,
        "password": password,
        "public_key": device_key.public_key_b64(key),
        "fp_hash": fingerprint.fingerprint_hash(),
    })
    if res.status_code != 200:
        raise ApiError(_error_text(res))
    device_id = res.json()["device_id"]
    device_key.save_device_id(device_id)
    return device_id


def build_login_payload(username: str, password: str, http=None, base=None) -> dict:
    """Asks the server for a one-time challenge and signs it with the device key."""
    http, base = _connection(http, base)
    device_id = device_key.load_device_id()
    if device_id is None:
        raise ApiError("This PC is not enrolled yet. Click 'Enroll this device' first.")

    res = _post(http, base, "/api/login/challenge", {"username": username})
    if res.status_code != 200:
        raise ApiError(_error_text(res))
    nonce = res.json()["nonce"]

    fp_hash = fingerprint.fingerprint_hash()
    key = device_key.load_or_create_key()
    return {
        "username": username,
        "password": password,
        "device_id": device_id,
        "nonce": nonce,
        "fp_hash": fp_hash,
        # we sign the nonce together with the fingerprint, so neither can be swapped
        "signature": device_key.sign(key, f"{nonce}|{fp_hash}"),
    }


def login(username: str, password: str, http=None, base=None) -> str:
    """Returns the one-time URL to open in the browser."""
    http, base = _connection(http, base)
    payload = build_login_payload(username, password, http, base)
    res = _post(http, base, "/api/login", payload)
    if res.status_code != 200:
        raise ApiError(_error_text(res))
    return res.json()["url"]
