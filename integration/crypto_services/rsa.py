from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .base64url import b64url_decode, b64url_encode

RSA_BITS = 4096


def generate_rsa4096_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    return priv, priv.public_key()


def public_key_to_b64url(pub: rsa.RSAPublicKey) -> str:
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64url_encode(der)


def load_public_key_b64url(pub_b64: str) -> rsa.RSAPublicKey:
    der = b64url_decode(pub_b64)
    pub = serialization.load_der_public_key(der)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Not an RSA public key")
    if pub.key_size != RSA_BITS:
        raise ValueError(f"RSA modulus must be {RSA_BITS} bits, got {pub.key_size}")
    return pub


def private_key_to_der(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key_der(der_priv: bytes) -> rsa.RSAPrivateKey:
    priv = serialization.load_der_private_key(der_priv, password=None)
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise ValueError("Not an RSA private key")
    if priv.public_key().key_size != RSA_BITS:
        raise ValueError(
            f"RSA modulus must be {RSA_BITS} bits, got {priv.public_key().key_size}"
        )
    return priv


def encrypt_rsa_oaep(plaintext: bytes, pub: rsa.RSAPublicKey) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if pub.key_size != RSA_BITS:
        raise ValueError(f"RSA modulus must be {RSA_BITS} bits, got {pub.key_size}")
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_rsa_oaep(ciphertext: bytes, priv: rsa.RSAPrivateKey) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    if priv.public_key().key_size != RSA_BITS:
        raise ValueError(
            f"RSA modulus must be {RSA_BITS} bits, got {priv.public_key().key_size}"
        )
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign_pss_sha256(message: bytes, priv: rsa.RSAPrivateKey) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if priv.public_key().key_size != RSA_BITS:
        raise ValueError(
            f"RSA modulus must be {RSA_BITS} bits, got {priv.public_key().key_size}"
        )
    return priv.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )


def verify_pss_sha256(message: bytes, signature: bytes, pub: rsa.RSAPublicKey) -> bool:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if pub.key_size != RSA_BITS:
        raise ValueError(f"RSA modulus must be {RSA_BITS} bits, got {pub.key_size}")
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

