import asyncio
import base64
import pathlib
import websockets
import uuid
import os
import time
import json

from .protocol import make_envelope, parse_envelope
from .customised_types import ServerMessageType, CustomisedMessageType, UserAuthType
from .crypto_services import (
    b64url_encode, b64url_decode,
    generate_rsa4096_keypair, private_key_to_der, public_key_to_b64url,
    encrypt_rsa_oaep, decrypt_rsa_oaep,
    sign_pss_sha256, verify_pss_sha256,
    load_public_key_b64url, load_private_key_der,
    preimage_dm, preimage_public, preimage_file_chunk, preimage_keyshare,
)
from .transport import verify_transport_payload
from .crypto_services.secure_store import get_password_hasher, protect_private_key, recover_private_key


DM_COMMAND = "/tell "
FILE_COMMAND = "/file "
LIST_COMMAND = "/list"
CLOSE_COMMAND = "/quit"
PUBLIC_COMMAND = "/all "
CHUNK_SIZE = 4096
RSA_OAEP_MAX_CHUNK = 512 - 2*32 - 2  # 4096-bit key, SHA-256 OAEP -> 446 bytes
REGISTER_COMMAND = "/register"
LOGIN_COMMAND = "/login "


class Client:
    def __init__(self):
        # Keys are set after login; generate ephemeral defaults
        priv, pub = generate_rsa4096_keypair()
        self._priv_der = private_key_to_der(priv)
        self._priv = priv
        self._pub_b64 = public_key_to_b64url(pub)
        self._server_pub = None
        self._peer_pub_cache = {}
        self._pending_pubkey = {}
        self._user_id = None
        self._login_future = None
        # Public channel state (stored, not used for encryption)
        self.public_group_version = None
        self.public_group_key = None

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
            payload={"user_id": user_id}
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
                await ws.send(msg)
                print(f"[REGISTER] Sent register request for {uid}")

            elif cmd.startswith(LOGIN_COMMAND):
                uid = cmd[len(LOGIN_COMMAND):].strip()
                if not uid:
                    print("[CLIENT] Usage: /login <user_id>")
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
                        payload={"client": "cli-v1", "pubkey": self._pub_b64, "enc_pubkey": self._pub_b64},
                        sig="",
                    )
                    await ws.send(hello)
                    print(f"[LOGIN SUCCESS] {uid}")
                else:
                    print(f"[LOGIN FAILED] {uid}: {resp.get('payload')}")

            if cmd.startswith(DM_COMMAND):
                try:
                    _, target, msg = cmd.split(" ", maxsplit=2)
                except ValueError:
                    print("[CLIENT] Usage: /tell <user_id> <message>")
                    continue
                if not self._user_id:
                    print("[CLIENT] Please /login first")
                    continue

                peer_pub_b64 = await self._ensure_peer_pub(ws, target)
                if not peer_pub_b64:
                    print(f"[CLIENT] No pubkey for {target}")
                    continue
                peer_pub = load_public_key_b64url(peer_pub_b64)
                plaintext = msg.encode("utf-8")
                ciphertext = b64url_encode(encrypt_rsa_oaep(plaintext, peer_pub))
                import time as _t
                ts_ms = int(_t.time() * 1000)
                pm = preimage_dm(ciphertext, self._user_id, target, ts_ms)
                content_sig = b64url_encode(sign_pss_sha256(pm, self._priv))
                dm = make_envelope(
                    msg_type="MSG_DIRECT",
                    from_id=self._user_id,
                    to_id=target,
                    payload={
                        "ciphertext": ciphertext,
                        "sender_pub": self._pub_b64,
                        "content_sig": content_sig
                    },
                    sig="",
                    ts=ts_ms
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

                # Ensure peer pubkey
                peer_pub_b64 = await self._ensure_peer_pub(ws, target)
                if not peer_pub_b64:
                    print("no peer pubkey")
                    continue
                peer_pub = load_public_key_b64url(peer_pub_b64)

                file_id = str(uuid.uuid4())
                size = os.path.getsize(filepath)
                name = os.path.basename(filepath)

                await ws.send(make_envelope(
                    msg_type="FILE_START",
                    from_id=self._user_id,
                    to_id=target,
                    payload={"file_id": file_id, "name": name, "size": size, "sender_pub": self._pub_b64},
                    sig="",
                    ts=int(time.time()*1000)
                ))

                ts_ms = int(time.time()*1000)
                with open(filepath, "rb") as f:
                    idx = 0
                    while True:
                        chunk = f.read(min(CHUNK_SIZE, RSA_OAEP_MAX_CHUNK))
                        if not chunk:
                            break
                        ct = encrypt_rsa_oaep(chunk, peer_pub)
                        ct_b64 = b64url_encode(ct)
                        total = (size + RSA_OAEP_MAX_CHUNK - 1) // RSA_OAEP_MAX_CHUNK
                        pm = preimage_file_chunk(ct_b64, self._user_id, target, ts_ms, file_id, idx, total)
                        sig_b64 = b64url_encode(sign_pss_sha256(pm, self._priv))
                        frame = {
                            "file_id": file_id,
                            "index": idx,
                            "total": total,
                            "ciphertext": ct_b64,
                            "sender_pub": self._pub_b64,
                            "content_sig": sig_b64,
                        }
                        await ws.send(make_envelope(
                            msg_type="FILE_CHUNK",
                            from_id=self._user_id,
                            to_id=target,
                            payload=frame,
                            sig="",
                            ts=ts_ms,
                        ))
                        idx += 1

                await ws.send(make_envelope(
                    msg_type="FILE_END",
                    from_id=self._user_id,
                    to_id=target,
                    payload={"file_id": file_id},
                    sig="",
                    ts=int(time.time()*1000)
                ))

            elif cmd.startswith(PUBLIC_COMMAND):
                text_bytes = cmd[len(PUBLIC_COMMAND):].encode("utf-8")
                if not self._user_id:
                    print("[CLIENT] Please /login first")
                    continue
                members, version = await self.get_public_members(ws)
                if not members:
                    print("[Public] no members")
                    continue
                label = f"public-v{self.public_group_version or version or 1}".encode()
                def iter_chunks(data: bytes, size: int):
                    for off in range(0, len(data), size):
                        yield data[off: off + size]
                for rid in members:
                    pub_b64 = self._pub_b64 if rid == self._user_id else await self._ensure_peer_pub(ws, rid)
                    if not pub_b64:
                        continue
                    pub = load_public_key_b64url(pub_b64)
                    for piece in iter_chunks(text_bytes, RSA_OAEP_MAX_CHUNK):
                        ts_ms = int(time.time()*1000)
                        ct_b64 = b64url_encode(encrypt_rsa_oaep(piece, pub, label=label))
                        pm = preimage_public(ct_b64, self._user_id, ts_ms)
                        content_sig = b64url_encode(sign_pss_sha256(pm, self._priv))
                        await ws.send(make_envelope(
                            msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                            from_id=self._user_id,
                            to_id=rid,
                            payload={"ciphertext": ct_b64, "sender_pub": self._pub_b64, "group_id": "public", "public_version": (self.public_group_version or version or 1), "content_sig": content_sig},
                            sig="",
                            ts=ts_ms,
                        ))

            elif cmd.startswith(LIST_COMMAND):
                lst_msg = make_envelope(
                    msg_type="LIST_REQUEST",
                    from_id=self._user_id or "",
                    to_id="server-1",
                    payload={}
                )
                await ws.send(lst_msg)

            elif cmd.startswith(CLOSE_COMMAND):
                ctrl = make_envelope(
                    msg_type="CTRL_CLOSE",
                    from_id=self._user_id or "",
                    to_id="server-1",
                    payload={}
                )
                await ws.send(ctrl)
                await ws.close(code=1000)
                print(f"[CLIENT:{self._user_id}] Disconnected")
                return

    async def receiver(self, ws):

        try:
            files_in_progress = {}
            async for raw in ws:
                frame = parse_envelope(raw)
                if not frame:
                    continue
                if frame["type"] == "ACK":
                    payload = frame.get("payload", {})
                    self._server_pub = payload.get("server_pub") or self._server_pub
                elif frame["type"] in [UserAuthType.LOGIN_SUCCESS, UserAuthType.LOGIN_FAIL]:
                    if self._login_future and not self._login_future.done():
                        self._login_future.set_result(frame)
                        self._login_future = None
                elif frame["type"] == "USER_DELIVER":
                    payload = frame.get("payload", {})
                    if self._server_pub and not verify_transport_payload(payload, frame.get("sig", ""), self._server_pub):
                        print("[ERROR] INVALID transport signature from server")
                        continue
                    sender_pub_b64 = payload.get("sender_pub")
                    ciphertext = payload.get("ciphertext", "")
                    pm = preimage_dm(ciphertext, payload.get("sender"), self._user_id, frame.get("ts") or 0)
                    if not sender_pub_b64 or not verify_pss_sha256(pm, b64url_decode(payload.get("content_sig", "")), load_public_key_b64url(sender_pub_b64)):
                        print("[ERROR] INVALID content signature")
                        continue
                    try:
                        pt = decrypt_rsa_oaep(b64url_decode(ciphertext), self._priv)
                        print(f"DM from {payload.get('sender')}: {pt.decode('utf-8', errors='replace')}")
                    except Exception:
                        print("[ERROR] Decrypt failed")
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
                        from .crypto_services import assert_valid_ts
                        assert_valid_ts(ts)
                    except Exception:
                        print("[Public] bad ts")
                        continue
                    if not verify_pss_sha256(preimage_public(ct_b64, sender, ts), b64url_decode(sig_b64), load_public_key_b64url(sender_pub_b64)):
                        print("[Public] bad content sig")
                        continue
                    ver = payload.get("public_version") or (self.public_group_version or 1)
                    label = f"public-v{ver}".encode()
                    try:
                        pt = decrypt_rsa_oaep(b64url_decode(ct_b64), self._priv, label=label)
                    except Exception:
                        print("[Public] decrypt failed")
                        continue
                    print(f"[Public] {sender}: {pt.decode('utf-8', errors='replace')}")
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
                        from .crypto_services import assert_valid_ts
                        assert_valid_ts(ts)
                    except Exception:
                        print("[FILE] bad ts; dropping")
                        continue
                    pm = preimage_file_chunk(p["ciphertext"], frame["from"], frame["to"], ts, fid, idx, total)
                    if not verify_pss_sha256(pm, b64url_decode(p.get("content_sig", "")), load_public_key_b64url(p.get("sender_pub", ""))):
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
                    outpath = pathlib.Path(f"received_{fid}")
                    outpath.write_bytes(out)
                    print(f"[FILE] saved {outpath} ({len(out)} bytes)")
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
                        if not verify_pss_sha256(pm, b64url_decode(content_sig), load_public_key_b64url(creator_pub)):
                            print("[Public] key-share signature invalid; ignoring")
                            continue
                    except Exception:
                        print("[Public] key-share verification error; ignoring")
                        continue
                    for s in shares:
                        if s.get("member") == self._user_id:
                            # Store wrapped key (we do not decrypt for RSA-only wire)
                            self.public_group_version = v
                            print(f"[Public] received key-share (v{v})")
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
                elif frame["type"] == CustomisedMessageType.LIST_RESPONSE:
                    online_users = frame.get("payload", {}).get("online_users")
                    print(f"Online users: {online_users}")
                elif frame["type"] == "ERROR":
                    print(f"[ERROR] {frame.get('payload')}")
        except websockets.exceptions.ConnectionClosedOK:
            print(f"[CLIENT:{self._user_id}] Connection closed normally by server.")
        except websockets.exceptions.ConnectionClosedError as e:
            print(f"[CLIENT:{self._user_id}] Connection lost unexpectedly: {e}")

    async def run_client(self, user_id=None, host="localhost", port=8765):
        uri = f"ws://{host}:{port}"

        try:
            async with websockets.connect(uri) as ws:
                print(f"[CLIENT:{self._user_id}] Connected to {uri}")
                await asyncio.gather(self.sender(ws), self.receiver(ws))        
        except (websockets.ConnectionClosedOK, websockets.ConnectionClosedError):
            print(f"[CLIENT:{self._user_id}] Server disconnected.")



    async def get_public_members(self, ws):
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        self._pending_pubkey["__public_members__"] = fut
        req = make_envelope(
            msg_type=ServerMessageType.PUBLIC_MEMBERS_SNAPSHOT,
            from_id=self._user_id,
            to_id="server-1",
            payload={}
        )
        await ws.send(req)
        try:
            resp = await fut
            members = resp.get("members", [])
            version = resp.get("version")
            return members, version
        finally:
            self._pending_pubkey.pop("__public_members__", None)


