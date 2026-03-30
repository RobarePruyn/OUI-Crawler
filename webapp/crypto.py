"""Fernet-based credential encryption for stored venue credentials."""

import base64
import hashlib

from cryptography.fernet import Fernet

from .config import settings

_SALT = b"oui-mapper-credential-encryption"


def _derive_key(secret: str) -> bytes:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), _SALT, 100_000)
    return base64.urlsafe_b64encode(dk)


_fernet = Fernet(_derive_key(settings.secret_key))


def encrypt_credential(plain: str) -> str:
    """Encrypt a plaintext credential for database storage."""
    return _fernet.encrypt(plain.encode()).decode()


def decrypt_credential(cipher: str) -> str:
    """Decrypt a stored credential back to plaintext."""
    return _fernet.decrypt(cipher.encode()).decode()
