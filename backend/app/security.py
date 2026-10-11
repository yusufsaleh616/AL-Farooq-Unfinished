"""Small crypto helpers: password hashing, token hashing, signature checks."""
import base64
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import PEPPER

_hasher = PasswordHasher()   # Argon2id with sane defaults

# A hash of a throwaway password. We verify against it when the username does
# not exist, so a wrong username takes about as long as a wrong password.
DUMMY_HASH = _hasher.hash("not-a-real-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def fp_hmac(fp_hash: str) -> str:
    """What we store for a device fingerprint: an HMAC with the server secret."""
    return hmac.new(PEPPER, fp_hash.encode(), hashlib.sha256).hexdigest()


def verify_signature(public_key_b64: str, message: str, signature_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature_b64), message.encode())
        return True
    except Exception:
        return False


def is_valid_public_key(public_key_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        return True
    except Exception:
        return False
