import json
from typing import Any, Dict, List

import hashlib
from .base64url import b64url_decode


def canonical_payload_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def assert_valid_ts(ts_ms: int) -> None:
    if not isinstance(ts_ms, int) or ts_ms <= 0:
        raise ValueError("invalid timestamp")


def _to_bytes(v: Any) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode("utf-8")
    if isinstance(v, int):
        return str(v).encode("ascii")
    raise TypeError("unsupported type")


def preimage_dm(ciphertext_b64url: str, from_id: str, to_id: str, ts_ms: int) -> bytes:
    c = b64url_decode(ciphertext_b64url)
    return c + _to_bytes(from_id) + _to_bytes(to_id) + _to_bytes(ts_ms)


def preimage_public(ciphertext_b64url: str, from_id: str, ts_ms: int) -> bytes:
    c = b64url_decode(ciphertext_b64url)
    return c + _to_bytes(from_id) + _to_bytes(ts_ms)


def preimage_file_chunk(
    ciphertext_b64url: str,
    from_id: str,
    to_id: str,
    ts_ms: int,
    file_id: str,
    index: int,
    total: int,
) -> bytes:
    c = b64url_decode(ciphertext_b64url)
    return (
        c
        + _to_bytes(from_id)
        + _to_bytes(to_id)
        + _to_bytes(ts_ms)
        + _to_bytes(file_id)
        + _to_bytes(index)
        + _to_bytes(total)
    )


def preimage_keyshare(shares_payload: List[dict], creator_pub_b64url: str) -> bytes:
    s = json.dumps(
        shares_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    digest = hashlib.sha256(s).digest()
    return digest + b64url_decode(creator_pub_b64url)


