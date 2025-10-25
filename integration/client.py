import asyncio
import base64
import json
import os
import hashlib
import pathlib
import time
import urllib.parse
import urllib.request
import uuid

import websockets

# Color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Text colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

def colorize(text, color):
    """Add color to text if terminal supports it"""
    try:
        # Check if we're in a terminal that supports colors
        if os.getenv('TERM') and os.getenv('TERM') != 'dumb':
            return f"{color}{text}{Colors.RESET}"
    except:
        pass
    return text

from crypto_services import (
    b64url_decode,
    b64url_encode,
    decrypt_rsa_oaep,
    encrypt_rsa_oaep,
    generate_rsa4096_keypair,
    load_private_key_der,
    load_public_key_b64url,
    preimage_dm,
    preimage_file_chunk,
    preimage_keyshare,
    preimage_public,
    private_key_to_der,
    public_key_to_b64url,
    sign_pss_sha256,
    verify_pss_sha256,
)
from crypto_services.secure_store import (
    get_password_hasher,
    protect_private_key,
    recover_private_key,
)
from customised_types import CustomisedMessageType, ServerMessageType, UserAuthType
from protocol import make_envelope, parse_envelope
from transport import verify_transport_payload

HTTP_DIR = os.getenv("HTTP_DIR", "http://127.0.0.1:8080")

DM_COMMAND = "/tell "
FILE_COMMAND = "/file "
LIST_COMMAND = "/list"
CLOSE_COMMAND = "/quit"
PUBLIC_COMMAND = "/all "
PUBLIC_COMMAND_ALT = "/public "
CHUNK_SIZE = 4096
PUBLIC_SEND_MODE = os.getenv("PUBLIC_SEND_MODE", "direct")
RSA_OAEP_MAX_CHUNK = 512 - 2 * 32 - 2  # 4096-bit key, SHA-256 OAEP -> 446 bytes
REGISTER_COMMAND = "/register"
LOGIN_COMMAND = "/login "


def _is_uuid_v4(s: str) -> bool:
    try:
        import uuid as _uuid

        return str(_uuid.UUID(s, version=4)) == s
    except Exception:
        return False


def _http_get_json(path: str, params: dict) -> dict:
    q = urllib.parse.urlencode(params)
    url = HTTP_DIR.rstrip("/") + path + ("?" + q if q else "")
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = resp.read()
        return json.loads(data.decode("utf-8"))


def _http_post_json(path: str, payload: dict) -> dict:
    url = HTTP_DIR.rstrip("/") + path
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        out = resp.read()
        return json.loads(out.decode("utf-8"))


class Client:
    def __init__(self):
        # Keys are set after login; generate ephemeral defaults
        priv, pub = generate_rsa4096_keypair()
        self._priv_der = private_key_to_der(priv)
        self._priv = priv
        self._pub_b64 = public_key_to_b64url(pub)
        self._server_pub = None
        self._server_id = None  
        self._peer_pub_cache = {}
        self._pending_pubkey = {}
        self._user_id = None
        self._name_cache = {}
        self._login_future = None
        self._register_future = None
        # Public channel state
        self.public_group_version = None
        self.public_group_key = None

    def _public_label(self, version: int) -> bytes:
        """Derive OAEP label for public channel using current group key.

        If group key is known, bind the label to ("public"|version|group_key) via SHA-256.
        Else, fall back to legacy version-only label for compatibility.
        """
        try:
            v_bytes = str(int(version or 1)).encode()
        except Exception:
            v_bytes = b"1"
        if self.public_group_key:
            h = hashlib.sha256()
            h.update(b"public|")
            h.update(v_bytes)
            h.update(b"|")
            h.update(self.public_group_key)
            return h.digest()
        return f"public-v{version or 1}".encode()

    def _label(self, uid: str) -> str:
        if not uid:
            return uid
        if uid in self._name_cache:
            return self._name_cache[uid]
        try:
            r = _http_get_json("/whois", {"user_id": uid})
            if r.get("ok"):
                self._name_cache[uid] = r["username"]
                return r["username"]
        except Exception:
            pass
        return uid

    async def _ensure_peer_pub(self, ws, user_id):
        if user_id in self._peer_pub_cache:
            return self._peer_pub_cache[user_id]
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        self._pending_pubkey[user_id] = fut
        req = make_envelope(
            msg_type="PUBKEY_REQUEST",
            from_id=self._user_id,
            to_id="server-1",
            payload={"user_id": user_id},
        )
        await ws.send(req)
        try:
            pub = await fut
            if pub:
                self._peer_pub_cache[user_id] = pub
            return pub
        finally:
            self._pending_pubkey.pop(user_id, None)

    async def sender(self, ws):
        loop = asyncio.get_event_loop()
        while True:
            cmd = await loop.run_in_executor(None, input)

            if cmd.startswith(REGISTER_COMMAND):
                uid = str(uuid.uuid4())
                print(f"Register for new user id {uid}")
                # 1) Ask for username FIRST (but do not claim yet)
                #    Optional pre-check: if /resolve finds it, prompt again.
                while True:
                    uname = input(
                        "Pick a username (3-32 chars, letters/digits/_): "
                    ).strip()
                    if not uname:
                        print("[REGISTER] Please enter a username.")
                        continue
                    try:
                        r = _http_get_json("/resolve", {"username": uname})
                        if r.get("ok"):
                            print(
                                "[REGISTER] That username is already taken. Try another."
                            )
                            continue
                    except Exception:
                        # 404 or any error -> treat as not found / available
                        pass
                    break
                # 2) Then ask for password
                password = input("Create password: ")
                # Generate keys and protect private key
                priv, pub = generate_rsa4096_keypair()
                priv_der = private_key_to_der(priv)
                enc_blob = protect_private_key(priv_der, password)
                ph = get_password_hasher()
                salted_hash = ph.hash(password)
                msg = make_envelope(
                    msg_type=UserAuthType.REGISTER,
                    from_id=uid,
                    to_id="server-1",
                    payload={
                        "pubkey": public_key_to_b64url(pub),
                        "privkey_store": b64url_encode(enc_blob),
                        "pake_password": salted_hash,
                    },
                    sig="",
                )
                loop = asyncio.get_event_loop()
                fut = loop.create_future()
                self._register_future = fut
                await ws.send(msg)
                print(
                    f"[REGISTER] Sent register request for {uid} (awaiting server ACK)"
                )
                try:
                    await fut
                except Exception:
                    print("[REGISTER] Failed before ACK; aborting username claim.")
                    self._register_future = None
                    continue
                finally:
                    self._register_future = None
                # 3) Claim the username (SOCP 9.1) once the user row exists
                # Add small delay to ensure user is fully registered in database
                await asyncio.sleep(0.1)
                try:
                    res = _http_post_json(
                        "/username/claim", {"user_id": uid, "username": uname}
                    )
                    if not res.get("ok"):
                        print(colorize("[REGISTER] Username not accepted:", Colors.RED), res)
                    else:
                        print(colorize(f"[REGISTER] Username '{uname}' claimed", Colors.GREEN))
                        self._name_cache[uid] = uname
                except Exception as e:
                    print(colorize("[REGISTER] Username claim failed:", Colors.RED), e)

            elif cmd.startswith(LOGIN_COMMAND):
                ident = cmd[len(LOGIN_COMMAND) :].strip()
                if not ident:
                    print("[CLIENT] Usage: /login <user_id|username>")
                    continue
                # Resolve username → UUID via directory
                if _is_uuid_v4(ident):
                    uid = ident
                else:
                    try:
                        r = _http_get_json("/resolve", {"username": ident})
                        if not r.get("ok"):
                            print("[CLIENT] Unknown username")
                            continue
                        uid = r.get("user_id")
                        name = ident
                        self._name_cache[uid] = name
                    except Exception as e:
                        print("[CLIENT] Resolve failed:", e)
                        continue
                password = input("Enter password: ")
                # Prepare waiter
                loop = asyncio.get_event_loop()
                fut = loop.create_future()
                self._login_future = fut
                req = make_envelope(
                    msg_type=UserAuthType.LOGIN_REQUEST,
                    from_id=uid,
                    to_id="server-1",
                    payload={"password": password},
                )
                await ws.send(req)
                # Wait for result
                resp = await fut
                if resp["type"] == UserAuthType.LOGIN_SUCCESS:
                    payload = resp.get("payload", {})
                    self._user_id = uid
                    self._pub_b64 = payload.get("pubkey", self._pub_b64)
                    enc = b64url_decode(payload.get("privkey_store", ""))
                    try:
                        der_priv = recover_private_key(enc, password)
                        self._priv_der = der_priv
                        self._priv = load_private_key_der(der_priv)
                    except Exception:
                        print("[CLIENT] Failed to recover private key")
                        continue
                    # Send USER_HELLO after login
                    hello = make_envelope(
                        "USER_HELLO",
                        from_id=self._user_id,
                        to_id="server-1",
                        payload={
                            "client": "cli-v1",
                            "pubkey": self._pub_b64,
                            "enc_pubkey": self._pub_b64,
                        },
                        sig="",
                    )
                    await ws.send(hello)
                    print(colorize(f"[LOGIN SUCCESS] {uid}", Colors.GREEN + Colors.BOLD))
                else:
                    print(colorize(f"[LOGIN FAILED] {uid}: {resp.get('payload')}", Colors.RED))

            if cmd.startswith(DM_COMMAND):
                try:
                    _, target, msg = cmd.split(" ", maxsplit=2)
                except ValueError:
                    print("[CLIENT] Usage: /tell <to_username|to_uuid> <message>")
                    continue
                if not self._user_id:
                    print("[CLIENT] Please /login first")
                    continue

                to_id = target
                try:
                    import uuid as _uuid

                    _ = _uuid.UUID(to_id, version=4)
                except Exception:
                    try:
                        r = _http_get_json("/resolve", {"username": to_id})
                        if not r.get("ok"):
                            print("[CLIENT] Unknown username")
                            continue
                        to_id = r.get("user_id")
                        self._name_cache[to_id] = target
                    except Exception as e:
                        print("[CLIENT] Resolve failed:", e)
                        continue

                peer_pub_b64 = await self._ensure_peer_pub(ws, to_id)
                if not peer_pub_b64:
                    print(f"[CLIENT] No pubkey for {to_id}")
                    continue
                peer_pub = load_public_key_b64url(peer_pub_b64)
                plaintext = msg.encode("utf-8")
                ciphertext = b64url_encode(encrypt_rsa_oaep(plaintext, peer_pub))
                import time as _t

                ts_ms = int(_t.time() * 1000)
                pm = preimage_dm(ciphertext, self._user_id, to_id, ts_ms)
                content_sig = b64url_encode(sign_pss_sha256(pm, self._priv))
                dm = make_envelope(
                    msg_type="MSG_DIRECT",
                    from_id=self._user_id,
                    to_id=to_id,
                    payload={
                        "ciphertext": ciphertext,
                        "sender_pub": self._pub_b64,
                        "content_sig": content_sig,
                    },
                    sig="",
                    ts=ts_ms,
                )
                await ws.send(dm)

            elif cmd.startswith(FILE_COMMAND):
                try:
                    _, target, filepath = cmd.split(" ", 2)
                except ValueError:
                    print("[CLIENT] Usage: /file <user_id> <path>")
                    continue
                if not self._user_id:
                    print("[CLIENT] Please /login first")
                    continue

                if not os.path.exists(filepath):
                    print(f"[CLIENT] File not found: {filepath}")
                    continue

                # Resolve username to UUID if needed
                to_id = target
                try:
                    import uuid as _uuid
                    _ = _uuid.UUID(to_id, version=4)
                except Exception:
                    try:
                        r = _http_get_json("/resolve", {"username": to_id})
                        if not r.get("ok"):
                            print("[CLIENT] Unknown username")
                            continue
                        to_id = r["user_id"]
                        self._name_cache[to_id] = target
                    except Exception as e:
                        print("[CLIENT] Resolve failed:", e)
                        continue

                # Ensure peer pubkey
                peer_pub_b64 = await self._ensure_peer_pub(ws, to_id)
                if not peer_pub_b64:
                    print("no peer pubkey")
                    continue
                peer_pub = load_public_key_b64url(peer_pub_b64)

                file_id = str(uuid.uuid4())
                size = os.path.getsize(filepath)
                name = os.path.basename(filepath)

                await ws.send(
                    make_envelope(
                        msg_type="FILE_START",
                        from_id=self._user_id,
                        to_id=to_id,
                        payload={
                            "file_id": file_id,
                            "name": name,
                            "size": size,
                            "sender_pub": self._pub_b64,
                        },
                        sig="",
                        ts=int(time.time() * 1000),
                    )
                )

                ts_ms = int(time.time() * 1000)
                with open(filepath, "rb") as f:
                    idx = 0
                    while True:
                        chunk = f.read(min(CHUNK_SIZE, RSA_OAEP_MAX_CHUNK))
                        if not chunk:
                            break
                        ct = encrypt_rsa_oaep(chunk, peer_pub)
                        ct_b64 = b64url_encode(ct)
                        total = (size + RSA_OAEP_MAX_CHUNK - 1) // RSA_OAEP_MAX_CHUNK
                        pm = preimage_file_chunk(
                            ct_b64, self._user_id, to_id, ts_ms, file_id, idx, total
                        )
                        sig_b64 = b64url_encode(sign_pss_sha256(pm, self._priv))
                        frame = {
                            "file_id": file_id,
                            "index": idx,
                            "total": total,
                            "ciphertext": ct_b64,
                            "sender_pub": self._pub_b64,
                            "content_sig": sig_b64,
                        }
                        await ws.send(
                            make_envelope(
                                msg_type="FILE_CHUNK",
                                from_id=self._user_id,
                                to_id=to_id,
                                payload=frame,
                                sig="",
                                ts=ts_ms,
                            )
                        )
                        idx += 1

                await ws.send(
                    make_envelope(
                        msg_type="FILE_END",
                        from_id=self._user_id,
                        to_id=to_id,
                        payload={"file_id": file_id},
                        sig="",
                        ts=int(time.time() * 1000),
                    )
                )

            elif cmd.startswith(PUBLIC_COMMAND) or cmd.startswith(PUBLIC_COMMAND_ALT):
                if cmd.startswith(PUBLIC_COMMAND):
                    text_bytes = cmd[len(PUBLIC_COMMAND) :].encode("utf-8")
                else:
                    text_bytes = cmd[len(PUBLIC_COMMAND_ALT) :].encode("utf-8")
                if not self._user_id:
                    print("[CLIENT] Please /login first")
                    continue
                members, version = await self.get_public_members(ws)
                if not members:
                    print("[Public] no members")
                    continue
                # Require installed group key for full SOCP compliance
                if not self.public_group_key:
                    print("[Public] group key not installed yet; waiting for key-share before sending")
                    continue
                label = self._public_label(self.public_group_version or version or 1)
                mode = PUBLIC_SEND_MODE
                if mode != "direct":
                    print("[Public] PUBLIC_SEND_MODE=broadcast requires a group key; falling back to direct per-recipient sends")

                def iter_chunks(data: bytes, size: int):
                    for off in range(0, len(data), size):
                        yield data[off : off + size]

                for rid in members:
                    pub_b64 = (
                        self._pub_b64
                        if rid == self._user_id
                        else await self._ensure_peer_pub(ws, rid)
                    )
                    if not pub_b64:
                        continue
                    pub = load_public_key_b64url(pub_b64)
                    for piece in iter_chunks(text_bytes, RSA_OAEP_MAX_CHUNK):
                        ts_ms = int(time.time() * 1000)
                        ct_b64 = b64url_encode(
                            encrypt_rsa_oaep(piece, pub, label=label)
                        )
                        pm = preimage_public(ct_b64, self._user_id, ts_ms)
                        content_sig = b64url_encode(sign_pss_sha256(pm, self._priv))
                        await ws.send(
                            make_envelope(
                                msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                                from_id=self._user_id,
                                to_id=rid,
                                payload={
                                    "ciphertext": ct_b64,
                                    "sender_pub": self._pub_b64,
                                    "group_id": "public",
                                    "public_version": (
                                        self.public_group_version or version or 1
                                    ),
                                    "content_sig": content_sig,
                                },
                                sig="",
                                ts=ts_ms,
                            )
                        )

            elif cmd.startswith(LIST_COMMAND):
                lst_msg = make_envelope(
                    msg_type="LIST_REQUEST",
                    from_id=self._user_id or "",
                    to_id=self._server_id or "server-1",
                    payload={},
                )
                await ws.send(lst_msg)

            elif cmd.startswith(CLOSE_COMMAND):
                ctrl = make_envelope(
                    msg_type="CTRL_CLOSE",
                    from_id=self._user_id or "",
                    to_id=self._server_id or "server-1",
                    payload={},
                )
                await ws.send(ctrl)
                await ws.close(code=1000)
                print(f"[CLIENT:{self._user_id}] Disconnected")
                return

    async def receiver(self, ws):
        files_in_progress = {}
        async for raw in ws:
            frame = parse_envelope(raw)
            if not frame:
                continue
            if frame["type"] == "CLIENT_WELCOME":
                payload = frame.get("payload", {}) or {}
                sid = payload.get("server_id") or frame.get("from")
                if sid:
                    self._server_id = sid
                # nothing else to do for welcome
                continue
            if frame["type"] == "ACK":
                payload = frame.get("payload", {})
                self._server_pub = payload.get("server_pub") or self._server_pub
                if payload.get("msg_ref") == "REGISTER_OK":
                    fut = self._register_future
                    if fut and not fut.done():
                        fut.set_result(True)
            elif frame["type"] in [UserAuthType.LOGIN_SUCCESS, UserAuthType.LOGIN_FAIL]:
                if self._login_future and not self._login_future.done():
                    self._login_future.set_result(frame)
                    self._login_future = None
            elif frame["type"] == "USER_DELIVER":
                payload = frame.get("payload", {})
                if self._server_pub and not verify_transport_payload(
                    payload, frame.get("sig", ""), self._server_pub
                ):
                    print("[ERROR] INVALID transport signature from server")
                    continue
                sender_pub_b64 = payload.get("sender_pub")
                ciphertext = payload.get("ciphertext", "")
                pm = preimage_dm(
                    ciphertext,
                    payload.get("sender"),
                    self._user_id,
                    frame.get("ts") or 0,
                )
                if not sender_pub_b64 or not verify_pss_sha256(
                    pm,
                    b64url_decode(payload.get("content_sig", "")),
                    load_public_key_b64url(sender_pub_b64),
                ):
                    print("[ERROR] INVALID content signature")
                    continue
                try:
                    pt = decrypt_rsa_oaep(b64url_decode(ciphertext), self._priv)
                    from_label = self._label(payload.get("sender"))
                    print(colorize(f"DM from {from_label}: {pt.decode('utf-8', errors='replace')}", Colors.CYAN))
                except Exception as e:
                    print(f"[ERROR] Decrypt failed: {e}")
                    print(f"  Ciphertext length: {len(ciphertext)}")
                    print(f"  Sender: {payload.get('sender')}")
                    print(f"  User ID: {self._user_id}")
                    print(f"  Private key available: {self._priv is not None}")
                    print(f"  My public key: {self._pub_b64[:50] if self._pub_b64 else 'None'}...")
            elif frame["type"] == ServerMessageType.MSG_PUBLIC_CHANNEL:
                payload = frame.get("payload", {})
                sender = frame.get("from")
                ts = frame.get("ts")
                ct_b64 = payload.get("ciphertext")
                sig_b64 = payload.get("content_sig")
                sender_pub_b64 = payload.get("sender_pub")
                if not (ct_b64 and sig_b64 and ts and sender_pub_b64):
                    print("[Public] missing fields")
                    continue
                try:
                    from crypto_services import assert_valid_ts

                    assert_valid_ts(ts)
                except Exception:
                    print("[Public] bad ts")
                    continue
                if not verify_pss_sha256(
                    preimage_public(ct_b64, sender, ts),
                    b64url_decode(sig_b64),
                    load_public_key_b64url(sender_pub_b64),
                ):
                    print("[Public] bad content sig")
                    continue
                ver = payload.get("public_version") or (self.public_group_version or 1)
                # Prefer group-key-bound label; fall back to legacy if not installed
                label = self._public_label(ver)
                try:
                    pt = decrypt_rsa_oaep(
                        b64url_decode(ct_b64), self._priv, label=label
                    )
                except Exception as e:
                    # Try legacy label if we failed and have a group key present (for mixed deployments)
                    try:
                        legacy_label = f"public-v{ver}".encode()
                        pt = decrypt_rsa_oaep(
                            b64url_decode(ct_b64), self._priv, label=legacy_label
                        )
                    except Exception:
                        print(f"[Public] decrypt failed: {e}")
                        print(f"  Ciphertext length: {len(ct_b64)}")
                        print(f"  Sender: {sender}")
                        print(f"  Version: {ver}")
                        print(f"  Private key available: {self._priv is not None}")
                        continue
                print(colorize(f"[Public] {self._label(sender)}: {pt.decode('utf-8', errors='replace')}", Colors.MAGENTA))
            elif frame["type"] == "PUBKEY_RESPONSE":
                payload = frame.get("payload", {})
                uid = payload.get("user_id")
                pub = payload.get("pubkey")
                fut = self._pending_pubkey.get(uid)
                if fut and not fut.done():
                    fut.set_result(pub)
            elif frame["type"] == "FILE_START":
                payload = frame.get("payload", {})
                fid = payload["file_id"]
                print(f"Receiving {payload['name']} ({payload['size']} bytes)")
                files_in_progress[fid] = []
            elif frame["type"] == "FILE_CHUNK":
                p = frame.get("payload", {})
                fid = p["file_id"]
                idx = int(p["index"])
                ts = frame["ts"]
                total = int(p.get("total", 0))
                try:
                    from crypto_services import assert_valid_ts

                    assert_valid_ts(ts)
                except Exception:
                    print("[FILE] bad ts; dropping")
                    continue
                pm = preimage_file_chunk(
                    p["ciphertext"], frame["from"], frame["to"], ts, fid, idx, total
                )
                if not verify_pss_sha256(
                    pm,
                    b64url_decode(p.get("content_sig", "")),
                    load_public_key_b64url(p.get("sender_pub", "")),
                ):
                    print("[FILE] bad content sig; dropping")
                    continue
                try:
                    chunk = decrypt_rsa_oaep(b64url_decode(p["ciphertext"]), self._priv)
                except Exception:
                    print("[FILE] decrypt failed; dropping")
                    continue
                files_in_progress.setdefault(fid, []).append(chunk)
            elif frame["type"] == "FILE_END":
                fid = frame.get("payload", {}).get("file_id")
                out = b"".join(files_in_progress.get(fid, []))
                # Save received file in integration folder
                integration_dir = os.path.dirname(os.path.abspath(__file__))
                outpath = pathlib.Path(integration_dir) / f"received_{fid}"
                outpath.write_bytes(out)
                print(colorize(f"[FILE] saved {outpath} ({len(out)} bytes)", Colors.GREEN))
                files_in_progress.pop(fid, None)
            elif frame["type"] == ServerMessageType.PUBLIC_CHANNEL_KEY_SHARE:
                payload = frame.get("payload", {})
                v = payload.get("version")
                shares = payload.get("shares", [])
                creator_pub = payload.get("creator_pub")
                content_sig = payload.get("content_sig", "")
                # Verify content signature over shares
                try:
                    pm = preimage_keyshare(shares, creator_pub)
                    if not verify_pss_sha256(
                        pm,
                        b64url_decode(content_sig),
                        load_public_key_b64url(creator_pub),
                    ):
                        print("[Public] key-share signature invalid; ignoring")
                        continue
                except Exception:
                    print("[Public] key-share verification error; ignoring")
                    continue
                # Use exact field name 'wrapped' if present to match signature preimage
                for s in shares:
                    if s.get("member") == self._user_id:
                        wrapped_b64 = s.get("wrapped")
                        if not wrapped_b64:
                            print("[Public] missing wrapped field in share; ignoring")
                            continue
                        try:
                            # Unwrap group key with RSA-OAEP label bound to version
                            label = f"public-v{v or 1}".encode()
                            gk = decrypt_rsa_oaep(b64url_decode(wrapped_b64), self._priv, label=label)
                            self.public_group_key = gk
                            self.public_group_version = v or self.public_group_version or 1
                            print(f"[Public] installed group key for v{self.public_group_version}")
                        except Exception as e:
                            print(f"[Public] failed to unwrap group key: {e}")
            elif frame["type"] == ServerMessageType.PUBLIC_CHANNEL_UPDATED:
                payload = frame.get("payload", {})
                new_v = payload.get("version")
                if new_v and new_v != self.public_group_version:
                    self.public_group_version = new_v
                    print(f"[Public] version now v{self.public_group_version}")
            elif frame["type"] == ServerMessageType.PUBLIC_MEMBERS_SNAPSHOT:
                payload = frame.get("payload", {})
                fut = self._pending_pubkey.get("__public_members__")
                if fut and not fut.done():
                    fut.set_result(payload)
                # Update the public group version from the snapshot
                snapshot_version = payload.get("version")
                if snapshot_version and snapshot_version != self.public_group_version:
                    self.public_group_version = snapshot_version
            elif frame["type"] == CustomisedMessageType.LIST_RESPONSE:
                online_users = frame.get("payload", {}).get("online_users")
                if online_users:
                    # Convert UUIDs to usernames
                    user_labels = []
                    for user_id in online_users:
                        label = self._label(user_id)
                        user_labels.append(label)
                    print(colorize(f"Online users: {user_labels}", Colors.BLUE + Colors.BOLD))
                else:
                    print(colorize("Online users: []", Colors.BLUE + Colors.BOLD))
            elif frame["type"] == "ERROR":
                print(colorize(f"[ERROR] {frame.get('payload')}", Colors.RED))

    async def run_client(self, user_id=None, host="localhost", port=8765):
        uri = f"ws://{host}:{port}"
        async with websockets.connect(uri) as ws:
            print(colorize(f"[CLIENT:{self._user_id}] Connected to {uri}", Colors.GREEN + Colors.BOLD))
            await asyncio.gather(self.sender(ws), self.receiver(ws))

    async def get_public_members(self, ws):
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        self._pending_pubkey["__public_members__"] = fut
        req = make_envelope(
            msg_type=ServerMessageType.PUBLIC_MEMBERS_SNAPSHOT,
            from_id=self._user_id,
            to_id=self._server_id or "server-1",
            payload={},
        )
        await ws.send(req)
        try:
            resp = await fut
            members = resp.get("members", [])
            version = resp.get("version")
            return members, version
        finally:
            self._pending_pubkey.pop("__public_members__", None)
