import json
import time
from typing import Any, Dict, Optional


def make_envelope(msg_type: str, from_id: str, to_id: str | None, payload: Dict[str, Any], sig: str = "", ts: Optional[int] = None) -> str:
    return json.dumps({
        "type": msg_type,
        "from": from_id,
        "to": to_id,
        "ts": int(time.time() * 1000) if ts is None else ts,
        "payload": payload,
        "sig": sig
    })


def parse_envelope(raw: str) -> Dict[str, Any] | None:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


