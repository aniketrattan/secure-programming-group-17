import json
import time

def make_envelope(msg_type: str, from_id, to_id, payload, sig=""):
    """Create JSON envelope"""
    return json.dumps({
        "type": msg_type,
        "from": from_id,
        "to": to_id,
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": sig
    })

def parse_envelope(raw):
    """Parse a received JSON frame"""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None
