from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16


def _kdf(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def protect_private_key(der_priv: bytes, password: str) -> bytes:
    salt = urandom(SALT_LEN)
    key = _kdf(password, salt)
    nonce = urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, der_priv, associated_data=None)
    return b"SC1" + salt + nonce + ct


def recover_private_key(blob: bytes, password: str) -> bytes:
    if not blob.startswith(b"SC1"):
        raise ValueError("bad blob")
    salt = blob[3 : 3 + SALT_LEN]
    nonce = blob[3 + SALT_LEN : 3 + SALT_LEN + NONCE_LEN]
    ct = blob[3 + SALT_LEN + NONCE_LEN :]
    key = _kdf(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)
