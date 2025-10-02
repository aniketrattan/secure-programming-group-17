import asyncio
import base64
import pathlib
import websockets
import uuid
import os

from .protocol import make_envelope, parse_envelope
from .customised_types import ServerMessageType, CustomisedMessageType
from .crypto_services import (
    b64url_encode, b64url_decode,
    generate_rsa4096_keypair, private_key_to_der, public_key_to_b64url,
    encrypt_rsa_oaep, decrypt_rsa_oaep,
    sign_pss_sha256, verify_pss_sha256,
    load_public_key_b64url, load_private_key_der,
    preimage_dm, preimage_public,
)
from .transport import verify_transport_payload


DM_COMMAND = "/tell "
FILE_COMMAND = "/file "
LIST_COMMAND = "/list"
CLOSE_COMMAND = "/quit"
PUBLIC_COMMAND = "/all "
CHUNK_SIZE = 4096


class Client:
    def __init__(self):
        priv, pub = generate_rsa4096_keypair()
        self._priv_der = private_key_to_der(priv)
        self._priv = priv
        self._pub_b64 = public_key_to_b64url(pub)
        self._server_pub = None
        self._peer_pub_cache = {}
        self._pending_pubkey = {}

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

    async def sender(self, ws, user_id):
        self._user_id = user_id
        loop = asyncio.get_event_loop()
        while True:
            cmd = await loop.run_in_executor(None, input)

            if cmd.startswith(DM_COMMAND):
                try:
                    _, target, msg = cmd.split(" ", maxsplit=2)
                except ValueError:
                    print("[CLIENT] Usage: /tell <user_id> <message>")
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
                pm = preimage_dm(ciphertext, user_id, target, ts_ms)
                content_sig = b64url_encode(sign_pss_sha256(pm, self._priv))
                dm = make_envelope(
                    msg_type="MSG_DIRECT",
                    from_id=user_id,
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

                if not os.path.exists(filepath):
                    print(f"[CLIENT] File not found: {filepath}")
                    continue

                file_id = str(uuid.uuid4())
                size = os.path.getsize(filepath)
                name = os.path.basename(filepath)

                manifest = {
                    "file_id": file_id,
                    "name": name,
                    "size": size,
                    "sha256": "demo",
                    "mode": "dm"
                }

                await ws.send(make_envelope(
                    msg_type="FILE_START",
                    from_id=user_id,
                    to_id=target,
                    payload=manifest
                ))

                with open(filepath, "rb") as f:
                    idx = 0
                    while chunk := f.read(CHUNK_SIZE):
                        b64 = base64.urlsafe_b64encode(chunk).decode().rstrip("=")
                        frame = {
                            "file_id": file_id,
                            "index": idx,
                            "ciphertext": b64
                        }
                        await ws.send(make_envelope(
                            msg_type="FILE_CHUNK",
                            from_id=user_id,
                            to_id=target,
                            payload=frame,
                            sig=""
                        ))
                        idx += 1

                await ws.send(make_envelope(
                    msg_type="FILE_END",
                    from_id=user_id,
                    to_id=target,
                    payload={"file_id": file_id},
                    sig=""
                ))

            elif cmd.startswith(PUBLIC_COMMAND):
                text = cmd[len(PUBLIC_COMMAND):]
                # For public, we still E2E encrypt to per-member wrapped key; here placeholder encrypt to string
                ciphertext = b64url_encode(text.encode('utf-8'))
                pm = preimage_public(ciphertext, user_id, 0)
                content_sig = b64url_encode(sign_pss_sha256(pm, self._priv))
                msg_public = make_envelope(
                    msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                    from_id=user_id,
                    to_id="public",
                    payload={
                        "ciphertext": ciphertext,
                        "sender_pub": self._pub_b64,
                        "content_sig": content_sig
                    },
                    sig=""
                )
                await ws.send(msg_public)

            elif cmd.startswith(LIST_COMMAND):
                lst_msg = make_envelope(
                    msg_type="LIST_REQUEST",
                    from_id=user_id,
                    to_id="server-1",
                    payload={}
                )
                await ws.send(lst_msg)

            elif cmd.startswith(CLOSE_COMMAND):
                ctrl = make_envelope(
                    msg_type="CTRL_CLOSE",
                    from_id=user_id,
                    to_id="server-1",
                    payload={}
                )
                await ws.send(ctrl)
                await ws.close(code=1000)
                print(f"[CLIENT:{user_id}] Disconnected")
                return

    async def receiver(self, ws):
        files_in_progress = {}
        async for raw in ws:
            frame = parse_envelope(raw)
            if not frame:
                continue
            if frame["type"] == "ACK":
                payload = frame.get("payload", {})
                self._server_pub = payload.get("server_pub") or self._server_pub
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
                print(f"[Public] {payload.get('ciphertext')}")
            elif frame["type"] == "PUBKEY_RESPONSE":
                payload = frame.get("payload", {})
                uid = payload.get("user_id")
                pub = payload.get("pubkey")
                fut = self._pending_pubkey.get(uid)
                if fut and not fut.done():
                    fut.set_result(pub)
            elif frame["type"] == "FILE_START":
                payload = frame.get("payload", {})
                print(f"Receiving file {payload['name']} ({payload['size']} bytes)")
                files_in_progress[payload["file_id"]] = []
            elif frame["type"] == "FILE_CHUNK":
                chunk = frame.get("payload", {})
                idx = int(chunk["index"])
                files_in_progress[chunk["file_id"]].insert(idx, base64.urlsafe_b64decode(chunk["ciphertext"] + "=="))
            elif frame["type"] == "FILE_END":
                fid = frame.get("payload", {}).get("file_id")
                data = b"".join(files_in_progress[fid])
                outpath = pathlib.Path(f"received_file_{fid}")
                outpath.write_bytes(data)
                print(f"File received and saved to {outpath}")
                del files_in_progress[fid]
            elif frame["type"] == CustomisedMessageType.LIST_RESPONSE:
                online_users = frame.get("payload", {}).get("online_users")
                print(f"Online users: {online_users}")
            elif frame["type"] == "ERROR":
                print(f"[ERROR] {frame.get('payload')}")

    async def run_client(self, user_id=None, host="localhost", port=8765):
        if not user_id:
            user_id = str(uuid.uuid4())
        uri = f"ws://{host}:{port}"
        async with websockets.connect(uri) as ws:
            print(f"[CLIENT:{user_id}] Connected to {uri}")
            hello = make_envelope(
                "USER_HELLO",
                from_id=user_id,
                to_id="server-1",
                payload={"client": "cli-v1", "pubkey": self._pub_b64, "enc_pubkey": self._pub_b64},
                sig=""
            )
            await ws.send(hello)
            await asyncio.gather(self.sender(ws, user_id), self.receiver(ws))


