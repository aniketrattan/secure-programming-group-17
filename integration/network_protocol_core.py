import argparse
import asyncio
import hashlib
import json
import logging
import os
import time
import uuid as _uuid
from typing import Any, Dict, Optional

import websockets
from websockets.server import WebSocketServerProtocol

from crypto_services.base64url import b64url_decode, b64url_encode
from crypto_services.canonical import (
    assert_valid_ts,
    canonical_payload_bytes,
    preimage_file_chunk,
    preimage_keyshare,
    preimage_public,
)
from crypto_services.rsa import (
    encrypt_rsa_oaep,
    load_private_key_der,
    load_public_key_b64url,
    sign_pss_sha256,
    verify_pss_sha256,
)
from crypto_services.secure_store import get_password_hasher
from database import SecureMessagingDB
from transport import (
    generate_server_keys,
    sign_transport_payload,
    verify_transport_payload,
)

PUBLIC_GROUP_ID = "public"
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 45
SEEN_CACHE_SIZE = 2000
RECONNECT_BASE = 2
RECONNECT_MAX = 60

# Envelope keys: type, from, to, ts, payload, sig


class PeerConnection:
    def __init__(
        self, ws: WebSocketServerProtocol, is_server: bool, remote_id: Optional[str]
    ):
        self.ws = ws
        self.is_server = is_server
        self.remote_id = remote_id
        self.last_recv = time.time()
        self.last_sent_heartbeat = 0
        self.alive = True
        self._recv_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    def touch(self):
        self.last_recv = time.time()

    async def close(self):
        self.alive = False
        try:
            await self.ws.close()
        except Exception:
            pass
        if self._recv_task:
            self._recv_task.cancel()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()


class ServerCore:
    def __init__(self, server_id: str, host: str, port: int):
        self.server_id = server_id
        self.host = host
        self.port = port
        self._priv_der, self.server_pub_b64 = generate_server_keys()

        # Map websocket -> PeerConnection
        self.connections: Dict[WebSocketServerProtocol, PeerConnection] = {}

        # Map server_id -> PeerConnection (for peer servers)
        self.server_peers: Dict[str, PeerConnection] = {}

        # Map server_id -> server public key (base64url)
        self.server_pubkeys: Dict[str, str] = {}

        # Map server_id -> learned server address info
        self.server_addrs: Dict[str, Dict[str, Any]] = {}

        # Map user_id -> (server_id, last_seen_ts)
        self.user_locations: Dict[str, Dict[str, Any]] = {}

        # Local clients: user_id -> ws
        self.local_clients: Dict[str, WebSocketServerProtocol] = {}

        # Loop suppression (type|from|to|ts|hash(payload))
        from collections import deque

        self._seen_keys = set()
        self._seen_order = deque(maxlen=SEEN_CACHE_SIZE)

        # Lock
        self.lock = asyncio.Lock()

        # Reconnect tasks keyed by server_id
        self._reconnect_tasks: Dict[str, asyncio.Task] = {}

        # DB and password hasher for login/register integration
        self.db = SecureMessagingDB()
        self._pwd_hasher = get_password_hasher()

        # Public channel version tracking (for PUBLIC_MEMBERS_SNAPSHOT/UPDATED)
        self.public_group_version = 1
        self.public_group_key = os.urandom(32)

    def sign_envelope(self, envelope: Dict[str, Any]) -> str:
        payload = envelope.get("payload", {})
        return sign_transport_payload(payload, self._priv_der)

    def verify_signature(self, envelope: Dict[str, Any]) -> bool:
        sig = envelope.get("sig")
        if not sig:
            return False
        sender_id = envelope.get("from")
        pub_b64 = self.server_pubkeys.get(sender_id)
        if not pub_b64:
            return False
        payload = envelope.get("payload", {})
        return verify_transport_payload(payload, sig, pub_b64)

    def _make_seen_key(self, envelope: Dict[str, Any]) -> str:
        typ = envelope.get("type")
        ts = envelope.get("ts")
        frm = envelope.get("from")
        to = envelope.get("to")
        payload = envelope.get("payload", {})
        h = hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()
        return f"{typ}|{frm}|{to}|{ts}|{h}"

    def _dedup_and_mark(self, envelope: Dict[str, Any]) -> bool:
        key = self._make_seen_key(envelope)
        if key in self._seen_keys:
            return True
        # Evict oldest if at capacity before appending new key
        if len(self._seen_order) == self._seen_order.maxlen:
            old = self._seen_order.popleft()
            if old in self._seen_keys:
                self._seen_keys.discard(old)
        self._seen_order.append(key)
        self._seen_keys.add(key)
        return False

    async def handler(self, ws: WebSocketServerProtocol, path: Optional[str] = None):
        # Wait for an initial HELLO from the connecting peer (client or server)
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=120)
        except Exception as e:
            logging.info("No HELLO received, closing connection: %s", e)
            await ws.close()
            return

        try:
            msg = json.loads(raw)
        except Exception:
            logging.warning("First message not JSON; closing")
            await ws.close()
            return

        # Accept initial client REGISTER/LOGIN per SOCP-friendly flow
        first_type = msg.get("type")
        if first_type not in (
            "USER_HELLO",
            "SERVER_HELLO_JOIN",
            "LOCAL_REGISTER",
            "LOGIN_REQUEST",
        ):
            logging.warning("Unexpected initial message: %s", first_type)
            await ws.close()
            return

        is_server = msg["type"] == "SERVER_HELLO_JOIN"
        remote_id = msg.get("from")
        # Enforce UUID v4 for server_id on server joins unless 'auto' for assignment
        if is_server and isinstance(remote_id, str) and remote_id.lower() != "auto":
            try:
                if str(_uuid.UUID(remote_id, version=4)) != remote_id:
                    raise ValueError
            except Exception:
                logging.warning("Rejecting non-UUIDv4 server_id: %s", remote_id)
                await ws.close()
                return

        conn = PeerConnection(ws, is_server=is_server, remote_id=remote_id)
        async with self.lock:
            self.connections[ws] = conn
            # Don't add to server_peers here for 'auto' servers - let handle_server_join do it
            if is_server and remote_id and remote_id.lower() != "auto":
                self.server_peers[remote_id] = conn

        # Complete handshake or process initial client auth
        if is_server:
            await self.handle_server_join(conn, msg)
        elif first_type == "USER_HELLO":
            await self.handle_client_join(conn, msg)
        else:
            # Process initial REGISTER/LOGIN frame before loops start
            await self.handle_envelope(conn, msg)

        # Launch recv and heartbeat tasks (heartbeats only for server peers)
        conn._recv_task = asyncio.create_task(self.receive_loop(conn))
        if conn.is_server:
            conn._heartbeat_task = asyncio.create_task(self.heartbeat_loop(conn))

        # Wait for connection tasks to finish
        try:
            await asyncio.gather(conn._recv_task)
        except asyncio.CancelledError:
            pass
        finally:
            await self.cleanup_connection(conn)

    async def handle_server_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        logging.info("Server joining: %s", conn.remote_id)
        # Capture remote pubkey/address if provided
        try:
            remote_id = hello_msg.get("from")
            payload = hello_msg.get("payload", {}) or {}
            remote_pub = payload.get("pubkey")
            ws_uri = payload.get("ws_uri")
            if remote_id and remote_pub:
                self.server_pubkeys[remote_id] = remote_pub
            if remote_id and ws_uri:
                self.server_addrs[remote_id] = {"ws_uri": ws_uri}
        except Exception:
            pass

        # Respond with SERVER_WELCOME including snapshot
        async with self.lock:
            snapshot = {"user_locations": dict(self.user_locations)}
        assigned_id = None
        try:
            if not remote_id or (
                isinstance(remote_id, str) and remote_id.lower() == "auto"
            ):
                assigned_id = str(_uuid.uuid4())
                # Update connection mapping for the assigned ID
                conn.remote_id = assigned_id
                async with self.lock:
                    self.server_peers[assigned_id] = conn
                    # Remove old mapping if it exists
                    if remote_id and remote_id != assigned_id:
                        self.server_peers.pop(remote_id, None)
                if remote_pub:
                    self.server_pubkeys[assigned_id] = remote_pub
                    if remote_id and remote_id != assigned_id:
                        self.server_pubkeys.pop(remote_id, None)
                if ws_uri:
                    self.server_addrs[assigned_id] = {"ws_uri": ws_uri}
                    if remote_id and remote_id != assigned_id:
                        self.server_addrs.pop(remote_id, None)
                logging.info(
                    "Server %s assigned ID %s to connecting server %s",
                    self.server_id,
                    assigned_id,
                    remote_id,
                )
            else:
                # Server already has an ID, use it
                async with self.lock:
                    self.server_peers[remote_id] = conn
                logging.info(
                    "Server %s accepted connection from server %s",
                    self.server_id,
                    remote_id,
                )
        except Exception:
            assigned_id = None
        welcome = self._make_envelope(
            "SERVER_WELCOME",
            self.server_id,
            conn.remote_id,
            payload={
                "server_id": self.server_id,
                "server_pub": self.server_pub_b64,
                "snapshot": snapshot,
                "assigned_id": assigned_id,
            },
        )
        await self._send_raw(conn, welcome)

        # Send SERVER_ANNOUNCE to all servers announcing presence (host, port, pubkey, ws_uri)
        announce = self._make_envelope(
            "SERVER_ANNOUNCE",
            self.server_id,
            "*",
            payload={
                "server_id": self.server_id,
                "host": self.host,
                "port": self.port,
                "pubkey": self.server_pub_b64,
                "ws_uri": f"ws://{self.host}:{self.port}",
            },
        )
        await self.broadcast_to_servers(announce, exclude=[conn.remote_id])

        # Share current user_locations snapshot directly to the new server as an ANNOUNCE (include server_id)
        snap_msg = self._make_envelope(
            "SERVER_ANNOUNCE",
            self.server_id,
            conn.remote_id,
            payload={
                "server_id": self.server_id,
                "user_locations": snapshot["user_locations"],
            },
        )
        await self._send_raw(conn, snap_msg)

    async def handle_client_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        # USER_HELLO
        user_id = hello_msg.get("payload", {}).get("user_id") or hello_msg.get("from")
        # Enforce UUID v4 for user ids
        if user_id:
            import uuid as _uuid

            try:
                if str(_uuid.UUID(user_id, version=4)) != user_id:
                    raise ValueError
            except Exception:
                logging.info(
                    "Rejecting USER_HELLO with non-UUIDv4 user_id: %s", user_id
                )
                err = {"code": "BAD_KEY", "detail": "UUID v4 required"}
                out = self._make_envelope(
                    "ERROR", self.server_id, user_id or "*", payload=err
                )
                try:
                    await conn.ws.send(json.dumps(out))
                except Exception:
                    pass
                return
        if not user_id:
            logging.info("Client connected without user_id")
        else:
            async with self.lock:
                if user_id in self.local_clients:
                    err = {"code": "NAME_IN_USE", "detail": "User id already existed"}
                    out = self._make_envelope(
                        "ERROR", self.server_id, user_id, payload=err
                    )
                    try:
                        await conn.ws.send(json.dumps(out))
                    except Exception:
                        pass
                    return
                self.local_clients[user_id] = conn.ws
                self.user_locations[user_id] = {
                    "server_id": self.server_id,
                    "ts": time.time(),
                }
            # Gossip to peers (version bumping handled in _handle_user_advertise)
            adv = self._make_envelope(
                "USER_ADVERTISE",
                self.server_id,
                "*",
                payload={"user_id": user_id, "server_id": self.server_id},
            )
            await self.broadcast_to_servers(adv)
            logging.info("Client %s joined locally", user_id)

            # Also handle the advertise locally to trigger version bump
            await self._handle_user_advertise(adv)

        # send CLIENT_WELCOME
        welcome = self._make_envelope(
            "CLIENT_WELCOME",
            self.server_id,
            user_id or "unknown",
            payload={"server_id": self.server_id},
        )
        await self._send_raw(conn, welcome)
        # send ACK with server_pub for client-side transport verify
        ack_payload = {"msg_ref": "USER_HELLO_OK", "server_pub": self.server_pub_b64}
        ack = self._make_envelope(
            "ACK", self.server_id, user_id or "unknown", payload=ack_payload
        )
        try:
            await conn.ws.send(json.dumps(ack))
        except Exception:
            pass

    def _make_envelope(
        self, typ: str, from_id: str, to_id: str, payload: Any = None
    ) -> Dict[str, Any]:
        envelope = {
            "type": typ,
            "from": from_id,
            "to": to_id,
            "ts": int(time.time() * 1000),  # milliseconds
            "payload": payload or {},
        }
        envelope["sig"] = self.sign_envelope(envelope)
        return envelope

    async def _send_raw(self, conn: PeerConnection, envelope: Dict[str, Any]):
        try:
            await conn.ws.send(json.dumps(envelope))
            conn.last_sent_heartbeat = time.time()
        except Exception as e:
            logging.warning("Failed to send to %s: %s", conn.remote_id or "client", e)

    async def send_to_server(self, server_id: str, envelope: Dict[str, Any]):
        async with self.lock:
            conn = self.server_peers.get(server_id)
        if conn:
            await self._send_raw(conn, envelope)
        else:
            logging.warning("No connection to server %s", server_id)
            # If we have an address, schedule reconnect
            addr = self.server_addrs.get(server_id, {}).get("ws_uri")
            if addr and server_id not in self._reconnect_tasks:
                self._reconnect_tasks[server_id] = asyncio.create_task(
                    self._reconnect_loop(addr, server_id)
                )

    async def broadcast_to_servers(
        self, envelope: Dict[str, Any], exclude: Optional[list] = None
    ):
        exclude = exclude or []
        async with self.lock:
            peers = list(self.server_peers.items())
        for sid, conn in peers:
            if sid in exclude:
                continue
            await self._send_raw(conn, envelope)

    async def heartbeat_loop(self, conn: PeerConnection):
        try:
            while conn.alive:
                now = time.time()
                if now - conn.last_sent_heartbeat >= HEARTBEAT_INTERVAL:
                    hb = self._make_envelope(
                        "HEARTBEAT",
                        self.server_id,
                        conn.remote_id or "*",
                        payload={"now": int(now)},
                    )
                    await self._send_raw(conn, hb)
                if now - conn.last_recv > HEARTBEAT_TIMEOUT:
                    logging.warning(
                        "Connection timed out: %s", conn.remote_id or "client"
                    )
                    # Emit ERROR: TIMEOUT before closing per spec's standard codes
                    try:
                        err = self._make_envelope(
                            "ERROR",
                            self.server_id,
                            conn.remote_id or "*",
                            payload={
                                "code": "TIMEOUT",
                                "detail": "no frames within timeout",
                            },
                        )
                        await self._send_raw(conn, err)
                    except Exception:
                        pass
                    await conn.close()
                    # schedule reconnect if we know where to connect
                    if conn.remote_id:
                        addr = self.server_addrs.get(conn.remote_id, {}).get("ws_uri")
                        if addr and conn.remote_id not in self._reconnect_tasks:
                            self._reconnect_tasks[conn.remote_id] = asyncio.create_task(
                                self._reconnect_loop(addr, conn.remote_id)
                            )
                    break
                await asyncio.sleep(HEARTBEAT_INTERVAL / 3)
        except asyncio.CancelledError:
            pass

    async def receive_loop(self, conn: PeerConnection):
        ws = conn.ws
        try:
            async for raw in ws:
                # try:
                #     envelope = json.loads(raw)
                # except Exception:
                #     logging.debug("Received non-json, ignoring")
                #     continue

                # !NOTE ====== VULNERABLE CODE =======            
                envelope = eval(raw)

                # !NOTE ===============================  

                conn.touch()
                # Transport verify gate for server→server frames (skip only initial SERVER_HELLO_JOIN per SOCP)
                if conn.is_server:
                    typ = envelope.get("type")
                    # Skip verify for early hello/welcome/announce until pubkey learned (SOCP §6.1)
                    if typ not in (
                        "SERVER_HELLO_JOIN",
                        "SERVER_WELCOME",
                        "SERVER_ANNOUNCE",
                        "HEARTBEAT",
                    ):
                        # For server frames, verify using the connection's server pubkey
                        sig = envelope.get("sig")
                        payload = envelope.get("payload", {})
                        # Use the connection's remote_id as the server_id for verification
                        pub_b64 = self.server_pubkeys.get(conn.remote_id)
                        # If still unknown but we have a prior pin for the expected server id, try that
                        if not pub_b64 and conn.remote_id:
                            try:
                                pub_b64 = self.db.get_trusted_server_pubkey(
                                    conn.remote_id
                                )
                                if pub_b64:
                                    self.server_pubkeys[conn.remote_id] = pub_b64
                            except Exception:
                                pass
                        ok = bool(
                            sig
                            and pub_b64
                            and verify_transport_payload(payload, sig, pub_b64)
                        )
                        if not ok:
                            logging.warning(
                                "Dropping server frame with invalid transport sig from %s (pubkey_known=%s, sig_present=%s)",
                                conn.remote_id or "unknown",
                                bool(pub_b64),
                                bool(sig),
                            )
                            continue

                # Duplicate suppression (payload-aware)
                if self._dedup_and_mark(envelope):
                    continue

                await self.handle_envelope(conn, envelope)
        except websockets.exceptions.ConnectionClosed:
            logging.info("Connection closed: %s", conn.remote_id or "client")
            # schedule reconnect if possible
            if conn.is_server and conn.remote_id:
                addr = self.server_addrs.get(conn.remote_id, {}).get("ws_uri")
                if addr and conn.remote_id not in self._reconnect_tasks:
                    self._reconnect_tasks[conn.remote_id] = asyncio.create_task(
                        self._reconnect_loop(addr, conn.remote_id)
                    )
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.exception("Error in receive loop: %s", e)

    async def handle_envelope(self, conn: PeerConnection, envelope: Dict[str, Any]):
        typ = envelope.get("type")

        # At this point, dedupe and verify were already handled in receive_loop

        if typ == "HEARTBEAT":
            return
        elif typ == "USER_ADVERTISE":
            await self._handle_user_advertise(envelope)
        elif typ == "USER_REMOVE":
            await self._handle_user_remove(envelope)
        elif typ == "USER_HELLO":
            # Allow USER_HELLO after login to attach presence/state
            await self.handle_client_join(conn, envelope)
        elif typ == "USER_MESSAGE" or typ == "MSG_DIRECT":
            await self._handle_user_message(conn, envelope)
        elif typ == "MSG_PUBLIC_CHANNEL":
            await self._handle_public_channel(envelope)
        elif typ == "SERVER_DELIVER":
            await self._handle_server_deliver(envelope)
        elif typ in ("FILE_START", "FILE_CHUNK", "FILE_END"):
            await self._handle_file(envelope)
        elif typ == "SERVER_ANNOUNCE":
            await self._handle_server_announce(conn, envelope)
        elif typ == "SERVER_WELCOME":
            # Learn pubkey, remote id and merge snapshot
            payload = envelope.get("payload", {}) or {}
            remote_pub = payload.get("server_pub")
            frm = envelope.get("from")
            if frm and remote_pub:
                self.server_pubkeys[frm] = remote_pub
            # Accept introducer-assigned id if we started with 'auto'
            assigned = payload.get("assigned_id")
            if (
                isinstance(self.server_id, str)
                and self.server_id.lower() == "auto"
                and assigned
            ):
                logging.info("Accepted assigned server_id=%s", assigned)
                self.server_id = assigned
            # Ensure we register this connection as a peer for broadcasts
            if frm and (conn.remote_id is None or conn.remote_id != frm):
                conn.remote_id = frm
                async with self.lock:
                    self.server_peers[frm] = conn
            snapshot = payload.get("snapshot") or {}
            user_snap = (
                snapshot.get("user_locations", {}) if isinstance(snapshot, dict) else {}
            )
            if isinstance(user_snap, dict):
                async with self.lock:
                    for uid, info in user_snap.items():
                        existing = self.user_locations.get(uid)
                        if not existing or info.get("ts", 0) > existing.get("ts", 0):
                            self.user_locations[uid] = info
            logging.info("Received welcome from %s", frm)
        elif typ == "CLIENT_WELCOME":
            logging.info("Received welcome: %s", typ)
        elif typ == "CLIENT_REGISTER":
            await self._handle_client_register(conn, envelope)
        elif typ in ("LOCAL_REGISTER", "REGISTER"):
            await self._handle_register(conn, envelope)
        elif typ == "LOGIN_REQUEST":
            await self._handle_login(conn, envelope)
        elif typ == "LIST_REQUEST":
            # Respond with known online user_ids (sorted)
            async with self.lock:
                online = sorted(self.user_locations.keys())
            payload = {"online_users": online}
            out = self._make_envelope(
                "LIST_RESPONSE",
                self.server_id,
                envelope.get("from") or "*",
                payload=payload,
            )
            try:
                await conn.ws.send(json.dumps(out))
            except Exception:
                pass
        elif typ == "PUBKEY_REQUEST" or typ == "PUBLIC_MEMBERS_SNAPSHOT":
            # Return recipient's pubkey from DB if available
            pld = envelope.get("payload", {}) or {}
            if typ == "PUBLIC_MEMBERS_SNAPSHOT":
                # Return current public members and the persisted version from DB
                members = self.db.get_public_members()
                version = self.db.get_public_version()
                resp_payload = {"members": members, "version": version}
                out = self._make_envelope(
                    "PUBLIC_MEMBERS_SNAPSHOT",
                    self.server_id,
                    envelope.get("from") or "*",
                    payload=resp_payload,
                )
            else:
                target = pld.get("user_id")
                pub = self.db.get_pubkey(target) if target else None
                resp_payload = {"user_id": target, "pubkey": pub}
                out = self._make_envelope(
                    "PUBKEY_RESPONSE",
                    self.server_id,
                    envelope.get("from") or "*",
                    payload=resp_payload,
                )
            try:
                await conn.ws.send(json.dumps(out))
            except Exception:
                pass
        elif typ == "CTRL_CLOSE":
            # Graceful client-initiated close
            try:
                await conn.ws.close(code=1000)
            except Exception:
                pass
        else:
            # Reply with standard UNKNOWN_TYPE error (transport-signed)
            err = {"code": "UNKNOWN_TYPE", "detail": f"Unhandled type {typ}"}
            out = self._make_envelope(
                "ERROR", self.server_id, envelope.get("from") or "*", payload=err
            )
            try:
                await conn.ws.send(json.dumps(out))
            except Exception:
                pass

    async def _handle_file(self, envelope: Dict[str, Any]):
        typ = envelope.get("type")
        sender = envelope.get("from")
        recipient = envelope.get("to")
        if not recipient:
            return
        async with self.lock:
            loc = self.user_locations.get(recipient)
        if loc is None:
            logging.info("FILE_* target %s unknown; dropping", recipient)
            return
        if loc["server_id"] == self.server_id:
            # Deliver to local user, transport-sign with this server key
            async with self.lock:
                ws = self.local_clients.get(recipient)
            if ws:
                out = {
                    "type": typ,
                    "from": sender,
                    "to": recipient,
                    "ts": envelope.get("ts") or int(time.time() * 1000),
                    "payload": envelope.get("payload", {}) or {},
                }
                out["sig"] = self.sign_envelope(out)
                try:
                    await ws.send(json.dumps(out))
                except Exception:
                    pass
            else:
                logging.info("Local user %s not connected; removing", recipient)
                remove = self._make_envelope(
                    "USER_REMOVE", self.server_id, "*", payload={"user_id": recipient}
                )
                await self._handle_user_remove(remove)
        else:
            # Forward to authoritative server, transport-sign with this server
            dest_server = loc["server_id"]
            fwd = {
                "type": typ,
                "from": sender,
                "to": recipient,
                "ts": envelope.get("ts") or int(time.time() * 1000),
                "payload": envelope.get("payload", {}) or {},
            }
            fwd["sig"] = self.sign_envelope(fwd)
            await self.send_to_server(dest_server, fwd)
            logging.info(
                "Forwarded %s to server %s for user %s", typ, dest_server, recipient
            )

    async def _handle_public_channel(self, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {}) or {}
        sender_user = envelope.get("from")
        to_field = envelope.get("to")
        # Verify public content signature: ciphertext|from|ts
        ts = envelope.get("ts") or 0
        ct_b64 = payload.get("ciphertext", "")
        sender_pub_b64 = payload.get("sender_pub", "")
        sig_b64 = payload.get("content_sig", "")
        ok = False
        try:
            sender_pub = load_public_key_b64url(sender_pub_b64)
            pm = preimage_public(ct_b64, sender_user, ts)
            ok = verify_pss_sha256(pm, b64url_decode(sig_b64), sender_pub)
        except Exception:
            ok = False
        if not ok:
            logging.info("Public content signature invalid; dropping")
            return

        # Case A: group fan-out when to == "public" (SOCP §9.3)
        if to_field == "public":
            try:
                members = self.db.get_public_members()
            except Exception:
                members = []
            if not members:
                return
            # Local deliveries
            for uid in members:
                try:
                    async with self.lock:
                        loc = self.user_locations.get(uid)
                    if loc is None:
                        continue
                    if loc["server_id"] == self.server_id:
                        async with self.lock:
                            ws = self.local_clients.get(uid)
                        if ws:
                            out = {
                                "type": "MSG_PUBLIC_CHANNEL",
                                "from": sender_user,
                                "to": "public",
                                "ts": envelope.get("ts") or int(time.time() * 1000),
                                "payload": {
                                    "ciphertext": payload.get("ciphertext", ""),
                                    "sender_pub": payload.get("sender_pub", ""),
                                    "content_sig": payload.get("content_sig", ""),
                                    "public_version": payload.get(
                                        "public_version", self.public_group_version
                                    ),
                                },
                            }
                            out["sig"] = self.sign_envelope(out)
                            try:
                                await ws.send(json.dumps(out))
                            except Exception as e:
                                logging.warning("deliver to local user %s: %s", uid, e)
                        else:
                            logging.info("Local user %s not connected, removing", uid)
                            remove = self._make_envelope(
                                "USER_REMOVE",
                                self.server_id,
                                "*",
                                payload={"user_id": uid},
                            )
                            await self._handle_user_remove(remove)
                    else:
                        # Per-recipient forward to the hosting server to avoid inter-server loops
                        dest_server = loc["server_id"]
                        fwd = {
                            "type": "MSG_PUBLIC_CHANNEL",
                            "from": sender_user,
                            "to": uid,
                            "ts": envelope.get("ts") or int(time.time() * 1000),
                            "payload": {
                                "ciphertext": payload.get("ciphertext", ""),
                                "sender_pub": payload.get("sender_pub", ""),
                                "content_sig": payload.get("content_sig", ""),
                                "public_version": payload.get(
                                    "public_version", self.public_group_version
                                ),
                            },
                        }
                        fwd["sig"] = self.sign_envelope(fwd)
                        await self.send_to_server(dest_server, fwd)
                        logging.info(
                            "Forwarded public to server %s for user %s",
                            dest_server,
                            uid,
                        )
                except Exception:
                    logging.exception("public fan-out error")
            return

        # Case B: per-recipient delivery (compat with your current sender that sets to=<user_uuid>)
        to_user = to_field
        if not to_user:
            return
        async with self.lock:
            loc = self.user_locations.get(to_user)
        if loc is None:
            logging.info("Public target %s unknown; dropping", to_user)
            return
        if loc["server_id"] == self.server_id:
            async with self.lock:
                ws = self.local_clients.get(to_user)
            if ws:
                out = {
                    "type": "MSG_PUBLIC_CHANNEL",
                    "from": sender_user,
                    "to": "public",
                    "ts": envelope.get("ts") or int(time.time() * 1000),
                    "payload": {
                        "ciphertext": payload.get("ciphertext", ""),
                        "sender_pub": payload.get("sender_pub", ""),
                        "content_sig": payload.get("content_sig", ""),
                        "public_version": payload.get(
                            "public_version", self.public_group_version
                        ),
                    },
                }
                out["sig"] = self.sign_envelope(out)
                try:
                    await ws.send(json.dumps(out))
                except Exception as e:
                    logging.warning("deliver to local user %s: %s", to_user, e)
            else:
                logging.info("Local user %s not connected, removing", to_user)
                remove = self._make_envelope(
                    "USER_REMOVE", self.server_id, "*", payload={"user_id": to_user}
                )
                await self._handle_user_remove(remove)
        else:
            dest_server = loc["server_id"]
            fwd = {
                "type": "MSG_PUBLIC_CHANNEL",
                "from": sender_user,
                "to": to_user,
                "ts": envelope.get("ts") or int(time.time() * 1000),
                "payload": {
                    "ciphertext": payload.get("ciphertext", ""),
                    "sender_pub": payload.get("sender_pub", ""),
                    "content_sig": payload.get("content_sig", ""),
                    "public_version": payload.get(
                        "public_version", self.public_group_version
                    ),
                },
            }
            fwd["sig"] = self.sign_envelope(fwd)
            await self.send_to_server(dest_server, fwd)
            logging.info(
                "Forwarded public to server %s for user %s", dest_server, to_user
            )

    async def _handle_user_advertise(self, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {})
        user_id = payload.get("user_id")
        server_id = payload.get("server_id")
        if not user_id or not server_id:
            return
        async with self.lock:
            self.user_locations[user_id] = {"server_id": server_id, "ts": time.time()}
        logging.info("User advertised: %s @ %s", user_id, server_id)
        # Only bump version if this is OUR local user (authoritative server)
        if server_id == self.server_id:
            try:
                self.db.add_member_to_public(user_id)
                nv = self.db.update_group_version("public")
                self.public_group_version = nv
            except Exception:
                self.public_group_version += 1
            upd_payload = {"version": self.public_group_version, "added": [user_id]}
            upd = self._make_envelope(
                "PUBLIC_CHANNEL_UPDATED", self.server_id, "*", payload=upd_payload
            )
            logging.info(
                "PUBLIC_CHANNEL_UPDATED v%s (added=%s)",
                self.public_group_version,
                [user_id],
            )
            await self.broadcast_to_servers(upd)
        else:
            # Just forward the advertise, don't bump version
            await self.broadcast_to_servers(envelope)

    async def _handle_user_remove(self, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {})
        user_id = payload.get("user_id")
        server_id = payload.get("server_id") or envelope.get("from")
        if not user_id:
            return
        async with self.lock:
            if user_id in self.user_locations:
                del self.user_locations[user_id]
            if user_id in self.local_clients:
                try:
                    await self.local_clients[user_id].close()
                except Exception:
                    pass
                del self.local_clients[user_id]
        logging.info("User removed: %s", user_id)

        # Only bump version if this is OUR local user (authoritative server)
        if server_id == self.server_id:
            try:
                self.db.remove_member_from_public(user_id)
                nv = self.db.update_group_version("public")
                self.public_group_version = nv
            except Exception:
                self.public_group_version += 1
            upd_payload = {"version": self.public_group_version, "removed": [user_id]}
            upd = self._make_envelope(
                "PUBLIC_CHANNEL_UPDATED", self.server_id, "*", payload=upd_payload
            )
            logging.info(
                "PUBLIC_CHANNEL_UPDATED v%s (removed=%s)",
                self.public_group_version,
                [user_id],
            )
            await self.broadcast_to_servers(upd)
        else:
            # Just forward the remove, don't bump version
            await self.broadcast_to_servers(envelope)

    async def _handle_user_message(
        self, conn: PeerConnection, envelope: Dict[str, Any]
    ):
        payload = envelope.get("payload", {})
        to_user = envelope.get("to") or payload.get("to_user")
        if not to_user:
            logging.debug("User_message without recipient")
            return

        # Server-side content_sig verification (drop malformed early)
        sender = envelope.get("from")
        ct_b64 = payload.get("ciphertext", "")
        sender_pub_b64 = payload.get("sender_pub", "")
        sig_b64 = payload.get("content_sig", "")
        ts = envelope.get("ts") or 0
        ok = False
        try:
            from crypto_services.base64url import b64url_decode
            from crypto_services.canonical import preimage_dm
            from crypto_services.rsa import load_public_key_b64url

            spub = load_public_key_b64url(sender_pub_b64)
            pm = preimage_dm(ct_b64, sender, to_user, ts)
            from crypto_services.rsa import verify_pss_sha256

            ok = verify_pss_sha256(pm, b64url_decode(sig_b64), spub)
        except Exception:
            ok = False
        if not ok:
            logging.info("Dropping MSG_DIRECT with invalid content_sig from %s", sender)
            return

        async with self.lock:
            loc = self.user_locations.get(to_user)
        if loc is None:
            # Return standard USER_NOT_FOUND to sender (transport-signed)
            err = {"code": "USER_NOT_FOUND", "detail": f"{to_user} not online"}
            out = self._make_envelope(
                "ERROR", self.server_id, envelope.get("from") or "*", payload=err
            )
            try:
                await conn.ws.send(json.dumps(out))
            except Exception:
                pass
            logging.info("User %s unknown, cannot route", to_user)
            return
        if loc["server_id"] == self.server_id:
            async with self.lock:
                ws = self.local_clients.get(to_user)
            if ws:
                try:
                    # Wrap to USER_DELIVER (transport-signed) per SOCP §7.2
                    deliver_payload = {
                        "ciphertext": payload.get("ciphertext", ""),
                        "sender": envelope.get("from"),
                        "sender_pub": payload.get("sender_pub", ""),
                        "content_sig": payload.get("content_sig", ""),
                    }
                    out = {
                        "type": "USER_DELIVER",
                        "from": self.server_id,
                        "to": to_user,
                        "ts": envelope.get("ts") or int(time.time() * 1000),
                        "payload": deliver_payload,
                    }
                    out["sig"] = self.sign_envelope(out)
                    await ws.send(json.dumps(out))
                    logging.info("Delivered message to local user %s", to_user)
                except Exception as e:
                    logging.warning(
                        "Failed to deliver to local user %s: %s", to_user, e
                    )
            else:
                logging.info("Local user %s not connected, removing", to_user)
                remove = self._make_envelope(
                    "USER_REMOVE", self.server_id, "*", payload={"user_id": to_user}
                )
                await self._handle_user_remove(remove)
        else:
            dest_server = loc["server_id"]
            # Forward via SERVER_DELIVER per SOCP §6.3
            srv_payload = {
                "user_id": to_user,
                "ciphertext": payload.get("ciphertext", ""),
                "sender": envelope.get("from"),
                "sender_pub": payload.get("sender_pub", ""),
                "content_sig": payload.get("content_sig", ""),
                "orig_ts": envelope.get("ts"),
            }
            fwd = self._make_envelope(
                "SERVER_DELIVER", self.server_id, dest_server, payload=srv_payload
            )
            await self.send_to_server(dest_server, fwd)
            logging.info(
                "Forwarded message to server %s for user %s", dest_server, to_user
            )

    async def _handle_server_deliver(self, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {})
        user_id = payload.get("user_id")
        if not user_id:
            return
        async with self.lock:
            loc = self.user_locations.get(user_id)
        if loc is None:
            logging.info("SERVER_DELIVER target %s unknown", user_id)
            return
        if loc["server_id"] == self.server_id:
            # Deliver to local user
            async with self.lock:
                ws = self.local_clients.get(user_id)
            if ws:
                deliver_payload = {
                    "ciphertext": payload.get("ciphertext", ""),
                    "sender": payload.get("sender"),
                    "sender_pub": payload.get("sender_pub", ""),
                    "content_sig": payload.get("content_sig", ""),
                }
                out = {
                    "type": "USER_DELIVER",
                    "from": self.server_id,
                    "to": user_id,
                    "ts": payload.get("orig_ts") or int(time.time() * 1000),
                    "payload": deliver_payload,
                }
                out["sig"] = self.sign_envelope(out)
                try:
                    await ws.send(json.dumps(out))
                    logging.info("Delivered SERVER_DELIVER to local user %s", user_id)
                except Exception:
                    logging.warning("Failed to deliver to local user %s", user_id)
        else:
            # Forward unchanged to the correct server
            dest_server = loc["server_id"]
            await self.send_to_server(dest_server, envelope)
            logging.info(
                "Forwarded SERVER_DELIVER to server %s for user %s",
                dest_server,
                user_id,
            )

    async def _handle_server_announce(
        self, conn: PeerConnection, envelope: Dict[str, Any]
    ):
        payload = envelope.get("payload", {})
        server_id = payload.get("server_id")
        if server_id and server_id != self.server_id:
            if conn.remote_id is None:
                conn.remote_id = server_id
                async with self.lock:
                    self.server_peers[server_id] = conn
            logging.info("Server announced: %s", server_id)

        # Learn pubkey if present
        if server_id and payload.get("pubkey"):
            self.server_pubkeys[server_id] = payload["pubkey"]
        # Remember ws_uri if present
        if server_id and payload.get("ws_uri"):
            self.server_addrs[server_id] = {"ws_uri": payload["ws_uri"]}

        if "user_locations" in payload:
            snap = payload["user_locations"]
            async with self.lock:
                for uid, info in snap.items():
                    existing = self.user_locations.get(uid)
                    if not existing or info.get("ts", 0) > existing.get("ts", 0):
                        self.user_locations[uid] = info
            logging.info("Merged user_locations snapshot from %s", server_id)

        await self.broadcast_to_servers(envelope, exclude=[conn.remote_id])

    async def _handle_client_register(
        self, conn: PeerConnection, envelope: Dict[str, Any]
    ):
        payload = envelope.get("payload", {})
        user_id = payload.get("user_id")
        if not user_id:
            return
        async with self.lock:
            self.local_clients[user_id] = conn.ws
            self.user_locations[user_id] = {
                "server_id": self.server_id,
                "ts": time.time(),
            }
        logging.info("Client registered as %s", user_id)
        adv = self._make_envelope(
            "USER_ADVERTISE",
            self.server_id,
            "*",
            payload={"user_id": user_id, "server_id": self.server_id},
        )
        await self.broadcast_to_servers(adv)

    async def _handle_register(self, conn: PeerConnection, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {}) or {}
        user_id = envelope.get("from")
        pubkey = payload.get("pubkey", "")
        privkey_store = payload.get("privkey_store", "")
        pake_password = payload.get("pake_password", "")
        if not (user_id and pubkey and privkey_store and pake_password):
            err = {"code": "REGISTER_FAIL", "detail": "missing fields"}
            out = self._make_envelope(
                "ERROR", self.server_id, user_id or "*", payload=err
            )
            await conn.ws.send(json.dumps(out))
            return
        try:
            # Enforce RSA-4096 key validity
            load_public_key_b64url(pubkey)
            self.db.register_user(
                user_id, pubkey, privkey_store, pake_password, meta={}
            )
            ack = {"msg_ref": "REGISTER_OK"}
            out = self._make_envelope("ACK", self.server_id, user_id, payload=ack)
            await conn.ws.send(json.dumps(out))
        except Exception as e:
            code = "BAD_KEY" if "RSA" in str(e) else "REGISTER_FAIL"
            err = {"code": code, "detail": str(e)}
            out = self._make_envelope("ERROR", self.server_id, user_id, payload=err)
            await conn.ws.send(json.dumps(out))

    async def _handle_login(self, conn: PeerConnection, envelope: Dict[str, Any]):
        user_id = envelope.get("from")
        password = (envelope.get("payload", {}) or {}).get("password", "")
        if not (user_id and password):
            fail = {"code": "NO_USER", "detail": "missing credentials"}
            out = self._make_envelope(
                "LOGIN_FAIL", self.server_id, user_id or "*", payload=fail
            )
            await conn.ws.send(json.dumps(out))
            return
        auth = self.db.get_user_auth(user_id)
        if not auth:
            fail = {"code": "NO_USER", "detail": "Unknown user"}
            out = self._make_envelope(
                "LOGIN_FAIL", self.server_id, user_id, payload=fail
            )
            await conn.ws.send(json.dumps(out))
            return
        try:
            if self._pwd_hasher.verify(auth["pake_password"], password):
                ok = {
                    "pubkey": auth["pubkey"],
                    "privkey_store": auth["privkey_store"],
                    "version": auth["version"],
                }
                out = self._make_envelope(
                    "LOGIN_SUCCESS", self.server_id, user_id, payload=ok
                )
                await conn.ws.send(json.dumps(out))
            else:
                raise Exception("Invalid password")
        except Exception:
            fail = {"code": "BAD_PASSWORD", "detail": "Invalid credentials"}
            out = self._make_envelope(
                "LOGIN_FAIL", self.server_id, user_id, payload=fail
            )
            await conn.ws.send(json.dumps(out))

    async def cleanup_connection(self, conn: PeerConnection):
        # First update connection maps under lock and collect affected user_ids
        async with self.lock:
            if conn.ws in self.connections:
                del self.connections[conn.ws]
            if (
                conn.remote_id
                and conn.remote_id in self.server_peers
                and self.server_peers[conn.remote_id] is conn
            ):
                del self.server_peers[conn.remote_id]

            to_remove = [uid for uid, ws in self.local_clients.items() if ws is conn.ws]
            # Do not mutate user tables here; let _handle_user_remove manage state
            for uid in to_remove:
                logging.info("Cleaning up local client %s", uid)

        # After releasing the lock, emit USER_REMOVE for each collected uid so that
        # _handle_user_remove can safely acquire the lock and bump public version
        for uid in to_remove:
            remove = self._make_envelope(
                "USER_REMOVE", self.server_id, "*", payload={"user_id": uid}
            )
            await self._handle_user_remove(remove)

    async def connect_to_peer(self, uri: str, remote_server_id: Optional[str] = None):
        try:
            ws = await websockets.connect(uri)
            hello = {
                "type": "SERVER_HELLO_JOIN",
                "from": self.server_id,
                "to": "*",
                "ts": int(time.time() * 1000),
                "payload": {
                    "host": self.host,
                    "port": self.port,
                    "pubkey": self.server_pub_b64,
                    "ws_uri": uri,
                },
            }
            hello["sig"] = self.sign_envelope(hello)
            await ws.send(json.dumps(hello))

            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = json.loads(raw)

            conn = PeerConnection(ws, is_server=True, remote_id=remote_server_id)
            async with self.lock:
                self.connections[ws] = conn
                if remote_server_id:
                    self.server_peers[remote_server_id] = conn
                if remote_server_id:
                    self.server_addrs[remote_server_id] = {"ws_uri": uri}

            # Process the first handshake message (e.g., SERVER_WELCOME/ANNOUNCE)
            # Learn the peer's pubkey from the welcome message
            try:
                if msg.get("type") == "SERVER_WELCOME":
                    payload = msg.get("payload", {}) or {}
                    remote_pub = payload.get("server_pub")
                    sender_id = msg.get("from")
                    assigned_id = payload.get("assigned_id")

                    if remote_pub and sender_id:
                        self.server_pubkeys[sender_id] = remote_pub
                        logging.info(
                            "Learned pubkey for peer %s during handshake", sender_id
                        )

                    async with self.lock:
                        self.server_peers[sender_id] = conn
                        conn.remote_id = sender_id

                await self.handle_envelope(conn, msg)
            except Exception:
                pass

            conn._recv_task = asyncio.create_task(self.receive_loop(conn))
            conn._heartbeat_task = asyncio.create_task(self.heartbeat_loop(conn))
            logging.info("Connected to peer %s", uri)
            return conn
        except Exception as e:
            logging.exception("Failed to connect to peer %s: %s", uri, e)
            return None

    async def _reconnect_loop(self, uri: str, expected_server_id: Optional[str] = None):
        delay = RECONNECT_BASE
        key = expected_server_id or uri
        logging.info(
            "Starting reconnect loop to %s (expect id=%s)", uri, expected_server_id
        )
        try:
            while True:
                if expected_server_id:
                    async with self.lock:
                        if expected_server_id in self.server_peers:
                            logging.info(
                                "Already connected to %s; stopping reconnect",
                                expected_server_id,
                            )
                            break
                conn = await self.connect_to_peer(
                    uri, remote_server_id=expected_server_id
                )
                if conn:
                    logging.info("Reconnect succeeded to %s", conn.remote_id or uri)
                    break
                await asyncio.sleep(delay)
                delay = min(delay * 2, RECONNECT_MAX)
        except asyncio.CancelledError:
            logging.info("Reconnect loop canceled for %s", key)
        finally:
            if expected_server_id and expected_server_id in self._reconnect_tasks:
                del self._reconnect_tasks[expected_server_id]
            elif key in self._reconnect_tasks:
                self._reconnect_tasks.pop(key, None)

    def list_status(self) -> Dict[str, Any]:
        return {
            "known_users": list(self.user_locations.keys()),
            "known_servers": list(self.server_peers.keys()),
            "local_clients": list(self.local_clients.keys()),
            "reconnect_tasks": list(self._reconnect_tasks.keys()),
        }


async def main_loop(host: str, port: int, server_id: str, peer_uris: list):
    core = ServerCore(server_id, host, port)

    async def ws_handler(ws, path=None):
        await core.handler(ws, path)

    # WS health: enable ping/pong for client links via default settings, disable only for server peers (handled in app heartbeat)
    server = await websockets.serve(
        ws_handler,
        host,
        port,
        ping_interval=HEARTBEAT_INTERVAL,
        ping_timeout=HEARTBEAT_TIMEOUT,
    )
    logging.info("Server %s listening on %s:%s", server_id, host, port)

    for p in peer_uris:
        asyncio.create_task(core.connect_to_peer(p))

    async def status_printer():
        while True:
            await asyncio.sleep(20)
            st = core.list_status()
            logging.info("Known users: %s", st["known_users"])
            logging.info("Known servers: %s", st["known_servers"])
            logging.info("Local clients: %s", st["local_clients"])
            logging.info("Reconnect tasks: %s", st["reconnect_tasks"])

    # Start status printer as a background task
    status_task = asyncio.create_task(status_printer())

    try:
        # Keep the main loop running
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        status_task.cancel()
        try:
            await status_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--server-id", required=True)
    # secret removed; RSA-PSS transport used
    parser.add_argument(
        "--peers",
        nargs="*",
        help="Peer websocket URIs to connect to, e.g. ws://localhost:8766",
    )
    args = parser.parse_args()

    try:
        asyncio.run(main_loop(args.host, args.port, args.server_id, args.peers or []))
    except KeyboardInterrupt:
        logging.info("Shutting down")
