import base64


def b64url_encode(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("b64url_encode expects bytes")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("b64url_decode expects str")
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


