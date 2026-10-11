"""The device's private key. It is created once, stays on this PC, and is used
to sign the server's login challenge. The server only ever sees the public key.

On Windows the key file is encrypted with DPAPI (tied to the Windows user).
Elsewhere it is stored as a plain file with owner-only permissions, which is
good enough for a demo but not for real use.
"""
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DPAPI = b"D"    # first byte of the key file says how it was stored
PLAIN = b"P"


def key_dir() -> Path:
    path = Path(os.getenv("ALFAROOQ_KEY_DIR", Path.home() / ".alfarooq"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _protect(raw: bytes) -> bytes:
    try:
        import win32crypt
    except ImportError:
        return PLAIN + raw
    return DPAPI + win32crypt.CryptProtectData(raw, "alfarooq", None, None, None, 0)


def _unprotect(blob: bytes) -> bytes:
    kind, data = blob[:1], blob[1:]
    if kind == DPAPI:
        import win32crypt
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
    return data


def load_or_create_key() -> Ed25519PrivateKey:
    path = key_dir() / "device.key"
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(_unprotect(path.read_bytes()))

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(_protect(raw))
    return key


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(key: Ed25519PrivateKey, message: str) -> str:
    return base64.b64encode(key.sign(message.encode())).decode()


def save_device_id(device_id: int):
    (key_dir() / "device.json").write_text(json.dumps({"device_id": device_id}))


def load_device_id():
    path = key_dir() / "device.json"
    if not path.exists():
        return None
    return json.loads(path.read_text()).get("device_id")
