from typing import Any, Dict, Tuple

from crypto_services.rsa import (
    generate_rsa4096_keypair,
    private_key_to_der,
    public_key_to_b64url,
    sign_pss_sha256,
    verify_pss_sha256,
    load_public_key_b64url,
    load_private_key_der,
)
from crypto_services.canonical import canonical_payload_bytes
from crypto_services.base64url import b64url_encode, b64url_decode


def generate_server_keys() -> Tuple[bytes, str]:
    priv, pub = generate_rsa4096_keypair()
    return private_key_to_der(priv), public_key_to_b64url(pub)


def sign_transport_payload(payload: Dict[str, Any], priv_der: bytes) -> str:
    priv = load_private_key_der(priv_der)
    data = canonical_payload_bytes(payload)
    sig = sign_pss_sha256(data, priv)
    return b64url_encode(sig)


def verify_transport_payload(payload: Dict[str, Any], sig_b64: str, pub_b64: str) -> bool:
    pub = load_public_key_b64url(pub_b64)
    data = canonical_payload_bytes(payload)
    try:
        return verify_pss_sha256(data, b64url_decode(sig_b64), pub)
    except Exception:
        return False


