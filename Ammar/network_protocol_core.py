 #added Introducer/bootstrap trust root using pinned introducer list
 #added ERROR: TIMEOUT frame emitted before closing idle server links

import asyncio
import json
import argparse
import logging
import time
import hmac
import hashlib
import base64
import sys
from typing import Dict, Any, Optional, Set, Deque, Tuple, List
from collections import deque

import websockets
from websockets.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Tunables
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 45
SEEN_CACHE_SIZE = 2000
RECONNECT_BASE = 2
RECONNECT_MAX = 60


def now_ms() -> int:
    return int(time.time() * 1000)


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64u_decode(s: str) -> bytes:
    padding_needed = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * padding_needed))


def canonical_payload_bytes(o: Any) -> bytes:
    return json.dumps(o or {}, separators=(",", ":"), sort_keys=True).encode()


class PeerConnection:
    def __init__(self, ws: WebSocketServerProtocol, is_server: bool, remote_id: Optional[str] = None, uri: Optional[str] = None):
        self.ws = ws
        self.is_server = is_server
        self.remote_id = remote_id
        self.uri = uri
        self.last_recv = time.time()
        self.last_sent = time.time()
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
    def __init__(self, server_id: str, secret: str, introducers: Dict[str, str]):
        self.server_id = server_id
        self.secret = secret.encode()
        # introducers: id -> secret 
        self.introducers: Dict[str, bytes] = {k: v.encode() for k, v in introducers.items()}

        # connections
        self.connections: Dict[WebSocketServerProtocol, PeerConnection] = {}
        self.server_peers: Dict[str, PeerConnection] = {}
        self.server_addrs: Dict[str, Dict[str, Any]] = {}

        # presence and routing
        self.user_locations: Dict[str, Dict[str, Any]] = {}
        self.local_clients: Dict[str, WebSocketServerProtocol] = {}

        # duplicate suppression
        self.seen: Set[str] = set()
        self.seen_q: Deque[str] = deque(maxlen=SEEN_CACHE_SIZE)

        # reconnect tasks
        self._reconnect_tasks: Dict[str, asyncio.Task] = {}

        self.lock = asyncio.Lock()

        logging.info("server core %s initialized (introducers: %s)", self.server_id, list(self.introducers.keys()))


    # Signing and verification

    def sign_envelope(self, env: Dict[str, Any], key: Optional[bytes] = None) -> str:
        # default sign with this server's secret
        secret = key if key is not None else self.secret
        to_sign = (str(env.get("type", "")) + "|" +
                   str(env.get("from", "")) + "|" +
                   str(env.get("to", "")) + "|" +
                   str(env.get("ts", ""))).encode()
        sig = hmac.new(secret, to_sign, hashlib.sha256).digest()
        return b64u_encode(sig)

    def verify_signature_with_secret(self, env: Dict[str, Any], secret: bytes) -> bool:
        sig = env.get("sig")
        if not sig:
            return False
        to_sign = (str(env.get("type", "")) + "|" +
                   str(env.get("from", "")) + "|" +
                   str(env.get("to", "")) + "|" +
                   str(env.get("ts", ""))).encode()
        expected = hmac.new(secret, to_sign, hashlib.sha256).digest()
        try:
            return hmac.compare_digest(expected, b64u_decode(sig))
        except Exception:
            return False

    def verify_signature(self, env: Dict[str, Any]) -> bool:
        # verify using our local secret (used for peers who share same secret in this demo)
        sig = env.get("sig")
        if not sig:
            return False
        expected = self.sign_envelope(env)
        try:
            return hmac.compare_digest(expected, sig)
        except Exception:
            return False

    def envelope_fingerprint(self, env: Dict[str, Any]) -> str:
        payload_hash = hashlib.sha256(canonical_payload_bytes(env.get("payload"))).hexdigest()
        key = f"{env.get('type','')}|{env.get('from','')}|{env.get('to','')}|{env.get('ts','')}|{payload_hash}"
        return hashlib.sha256(key.encode()).hexdigest()


    # Handler
 
    async def handler(self, ws: WebSocketServerProtocol, path: Optional[str] = None):
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
        except Exception as e:
            logging.info("No HELLO received from connection: %s", e)
            await ws.close()
            return

        try:
            msg = json.loads(raw)
        except Exception:
            logging.warning("First message not JSON; closing")
            await ws.close()
            return

        t = msg.get("type")
        if t not in ("CLIENT_HELLO", "CLIENT_REGISTER", "SERVER_HELLO_JOIN"):
            logging.warning("Unexpected initial message type: %s", t)
            await ws.close()
            return

        is_server = t == "SERVER_HELLO_JOIN"
        remote_id = msg.get("from")
        conn = PeerConnection(ws, is_server=is_server, remote_id=remote_id)
        async with self.lock:
            self.connections[ws] = conn
            if is_server and remote_id:
                self.server_peers[remote_id] = conn

        # If it's a server HELLO, verify signature if it's from a pinned introducer (optional)
        if is_server and remote_id and remote_id in self.introducers:
            # the incoming HELLO should be signed by that introducer's secret
            if not self.verify_signature_with_secret(msg, self.introducers[remote_id]):
                logging.warning("Invalid signature on SERVER_HELLO_JOIN from pinned introducer %s; closing", remote_id)
                await ws.close()
                async with self.lock:
                    self.connections.pop(ws, None)
                return

        # process join flows
        if is_server:
            await self.handle_server_join(conn, msg)
        else:
            await self.handle_client_join(conn, msg)

        # start loops
        conn._recv_task = asyncio.create_task(self.receive_loop(conn))
        conn._heartbeat_task = asyncio.create_task(self.heartbeat_loop(conn))
        try:
            await conn._recv_task
        except asyncio.CancelledError:
            pass
        finally:
            await self.cleanup_connection(conn)


    # Bootstrapping flows

    async def handle_server_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        logging.info("Incoming SERVER_HELLO_JOIN from: %s", conn.remote_id)
        payload = hello_msg.get("payload", {}) or {}
        remote_from = hello_msg.get("from")
        ws_uri = payload.get("ws_uri")
        if remote_from and ws_uri:
            async with self.lock:
                self.server_addrs[remote_from] = {"ws_uri": ws_uri}

        # SERVER_WELCOME (include snapshot)
        async with self.lock:
            snapshot = {"user_locations": dict(self.user_locations)}
        welcome = {
            "type": "SERVER_WELCOME",
            "from": self.server_id,
            "to": remote_from or "*",
            "ts": now_ms(),
            "payload": {"server_id": self.server_id, "snapshot": snapshot}
        }
        welcome["sig"] = self.sign_envelope(welcome)
        await self._send_raw(conn, welcome)

        #SERVER_ANNOUNCE to other peers (exclude joining one)
        announce_payload = {"server_id": self.server_id, "user_locations": dict(self.user_locations)}
        announce = {
            "type": "SERVER_ANNOUNCE",
            "from": self.server_id,
            "to": "*",
            "ts": now_ms(),
            "payload": announce_payload
        }
        announce["sig"] = self.sign_envelope(announce)
        await self.broadcast_to_servers(announce, exclude=[conn.remote_id])

    async def handle_client_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        payload = hello_msg.get("payload", {}) or {}
        user_id = payload.get("user_id") or hello_msg.get("from")
        if user_id:
            async with self.lock:
                self.local_clients[user_id] = conn.ws
                self.user_locations[user_id] = {"server_id": self.server_id, "ts": time.time()}
            adv = {
                "type": "USER_ADVERTISE",
                "from": self.server_id,
                "to": "*",
                "ts": now_ms(),
                "payload": {"user_id": user_id, "server_id": self.server_id}
            }
            adv["sig"] = self.sign_envelope(adv)
            await self.broadcast_to_servers(adv)
            logging.info("Client %s joined locally", user_id)
        welcome = {"type": "CLIENT_WELCOME", "from": self.server_id, "to": user_id or "unknown", "ts": now_ms(),
                   "payload": {"server_id": self.server_id}}
        welcome["sig"] = self.sign_envelope(welcome)
        await self._send_raw(conn, welcome)


    #receive loop and heartbeat
    async def receive_loop(self, conn: PeerConnection):
        ws = conn.ws
        try:
            async for raw in ws:
                try:
                    envelope = json.loads(raw)
                except Exception:
                    logging.debug("Received non-json; ignoring")
                    continue

                conn.touch()

                # if from server, enforce signature using current model:
                # if this sender is a pinned introducer, verify with introducer secret
                # else try verify with this server's secret (demo HMAC model)
                if conn.is_server:
                    sender = envelope.get("from")
                    if sender and sender in self.introducers:
                        if not self.verify_signature_with_secret(envelope, self.introducers[sender]):
                            logging.warning("Dropping frame with invalid signature from introducer %s", sender)
                            continue
                    else:
                        if not self.verify_signature(envelope):
                            logging.warning("Dropping server frame with invalid signature from %s", conn.remote_id or "unknown")
                            continue

                # duplicate suppression
                fid = self.envelope_fingerprint(envelope)
                if fid in self.seen:
                    logging.debug("Dropping duplicate envelope %s from %s", envelope.get("type"), envelope.get("from"))
                    continue
                self.seen.add(fid)
                self.seen_q.append(fid)
                if len(self.seen_q) == self.seen_q.maxlen:
                    if len(self.seen) > self.seen_q.maxlen:
                        self.seen = set(self.seen_q)

                await self.handle_envelope(conn, envelope)
        except ConnectionClosed:
            logging.info("Connection closed: %s", conn.remote_id or "client")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.exception("Error in receive_loop: %s", e)

    async def heartbeat_loop(self, conn: PeerConnection):
        try:
            while conn.alive:
                now = time.time()
                if now - conn.last_sent >= HEARTBEAT_INTERVAL:
                    hb = {"type": "HEARTBEAT", "from": self.server_id, "to": conn.remote_id or "*", "ts": now_ms(), "payload": {}}
                    hb["sig"] = self.sign_envelope(hb)
                    await self._send_raw(conn, hb)
                if now - conn.last_recv > HEARTBEAT_TIMEOUT:
                    logging.warning("Connection timed out (no recv) for %s", conn.remote_id or "peer")
                    # send ERROR: TIMEOUT before closing
                    try:
                        err = {"type": "ERROR", "from": self.server_id, "to": conn.remote_id or "*", "ts": now_ms(),
                               "payload": {"reason": "TIMEOUT"}}
                        err["sig"] = self.sign_envelope(err)
                        await self._send_raw(conn, err)
                        logging.info("Sent ERROR:TIMEOUT to %s", conn.remote_id or conn.uri or "peer")
                    except Exception:
                        logging.exception("Failed to send ERROR:TIMEOUT")
                    await conn.close()
                    # schedule reconnect if we know addr
                    if conn.remote_id:
                        addr = self.server_addrs.get(conn.remote_id, {}).get("ws_uri")
                        if addr and conn.remote_id not in self._reconnect_tasks:
                            self._reconnect_tasks[conn.remote_id] = asyncio.create_task(self._reconnect_loop(addr, conn.remote_id))
                    break
                await asyncio.sleep(HEARTBEAT_INTERVAL / 3)
        except asyncio.CancelledError:
            pass

    #dispatch envelope 
    async def handle_envelope(self, conn: PeerConnection, envelope: Dict[str, Any]):
        typ = envelope.get("type")
        if not typ:
            return

        if typ == "HEARTBEAT":
            return
        if typ == "USER_ADVERTISE":
            await self._handle_user_advertise(envelope)
        elif typ == "USER_REMOVE":
            await self._handle_user_remove(envelope)
        elif typ in ("USER_MESSAGE", "MSG_DIRECT", "MSG_PRIVATE"):
            await self._handle_user_message(envelope)
        elif typ == "SERVER_ANNOUNCE":
            await self._handle_server_announce(conn, envelope)
        elif typ == "SERVER_WELCOME":
            await self._handle_server_welcome(conn, envelope)
        elif typ == "SERVER_DELIVER":
            await self._handle_server_deliver(envelope)
        elif typ == "CLIENT_REGISTER":
            await self._handle_client_register(conn, envelope)
        elif typ == "ERROR":
            logging.info("Received ERROR frame from %s: %s", envelope.get("from"), envelope.get("payload"))
        else:
            logging.debug("Unhandled envelope type: %s", typ)

    #handlers
    async def _handle_user_advertise(self, envelope: Dict[str, Any]):
        p = envelope.get("payload", {}) or {}
        uid = p.get("user_id")
        sid = p.get("server_id") or envelope.get("from")
        if not uid or not sid:
            return
        async with self.lock:
            self.user_locations[uid] = {"server_id": sid, "ts": time.time()}
        logging.info("User advertised: %s @ %s", uid, sid)
        await self.broadcast_to_servers(envelope)

    async def _handle_user_remove(self, envelope: Dict[str, Any]):
        p = envelope.get("payload", {}) or {}
        uid = p.get("user_id")
        sid = p.get("server_id") or envelope.get("from")
        if not uid:
            return
        async with self.lock:
            cur = self.user_locations.get(uid)
            if cur and cur.get("server_id") == sid:
                del self.user_locations[uid]
            if uid in self.local_clients:
                try:
                    await self.local_clients[uid].close()
                except Exception:
                    pass
                del self.local_clients[uid]
        logging.info("User removed: %s (announced by %s)", uid, sid)
        await self.broadcast_to_servers(envelope)

    async def _handle_user_message(self, envelope: Dict[str, Any]):
        p = envelope.get("payload", {}) or {}
        to_user = envelope.get("to") or p.get("to_user") or p.get("recipient")
        if not to_user:
            logging.debug("User_message without recipient")
            return
        async with self.lock:
            loc = self.user_locations.get(to_user)
        if not loc:
            logging.info("User %s unknown; cannot route", to_user)
            return
        if loc["server_id"] == self.server_id:
            async with self.lock:
                ws = self.local_clients.get(to_user)
            if ws:
                try:
                    await ws.send(json.dumps(envelope))
                    logging.info("Delivered message to local user %s", to_user)
                except Exception as e:
                    logging.warning("Failed to deliver to local user %s: %s", to_user, e)
            else:
                logging.info("Local user %s not connected; removing mapping", to_user)
                remove = {"type": "USER_REMOVE", "from": self.server_id, "to": "*", "ts": now_ms(),
                          "payload": {"user_id": to_user, "server_id": self.server_id}}
                remove["sig"] = self.sign_envelope(remove)
                await self._handle_user_remove(remove)
        else:
            dest = loc["server_id"]
            await self.send_to_server(dest, envelope)
            logging.info("Forwarded message to server %s for user %s", dest, to_user)

    async def _handle_server_announce(self, conn: PeerConnection, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {}) or {}
        sid = payload.get("server_id") or envelope.get("from")
        if sid and sid != self.server_id:
            if conn.remote_id is None:
                conn.remote_id = sid
                async with self.lock:
                    self.server_peers[sid] = conn
            ws_uri = payload.get("ws_uri")
            if ws_uri:
                async with self.lock:
                    self.server_addrs[sid] = {"ws_uri": ws_uri}
            logging.info("Server announced: %s", sid)
        if "user_locations" in payload:
            snap = payload["user_locations"]
            async with self.lock:
                for uid, info in (snap.items() if isinstance(snap, dict) else []):
                    existing = self.user_locations.get(uid)
                    if not existing or info.get("ts", 0) > existing.get("ts", 0):
                        self.user_locations[uid] = info
            logging.info("Merged user_locations snapshot from %s", sid)
        await self.broadcast_to_servers(envelope, exclude=[conn.remote_id])

    async def _handle_server_welcome(self, conn: PeerConnection, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {}) or {}
        sid = payload.get("server_id") or envelope.get("from")
        # If welcome came from a pinned introducer, verify with its secret before accepting
        sender = envelope.get("from")
        if sender in self.introducers:
            ok = self.verify_signature_with_secret(envelope, self.introducers[sender])
            if not ok:
                logging.warning("SERVER_WELCOME from pinned introducer %s failed signature check; rejecting", sender)
                try:
                    await conn.ws.close()
                except Exception:
                    pass
                return
            logging.info("Verified SERVER_WELCOME from pinned introducer %s", sender)
        # register peer
        if sid:
            conn.remote_id = sid
            async with self.lock:
                self.server_peers[sid] = conn
        # merge snapshot if present
        snapshot = payload.get("snapshot") or {}
        user_snap = snapshot.get("user_locations", {}) if isinstance(snapshot, dict) else {}
        async with self.lock:
            for uid, info in (user_snap.items() if isinstance(user_snap, dict) else []):
                existing = self.user_locations.get(uid)
                if not existing or info.get("ts", 0) > existing.get("ts", 0):
                    self.user_locations[uid] = info
        logging.info("Processed SERVER_WELCOME from %s", sid or sender)

    async def _handle_server_deliver(self, envelope: Dict[str, Any]):
        payload = envelope.get("payload", {}) or {}
        user_id = payload.get("user_id") or envelope.get("to")
        if not user_id:
            logging.debug("SERVER_DELIVER missing user_id")
            return
        async with self.lock:
            loc = self.user_locations.get(user_id)
        if not loc:
            logging.info("SERVER_DELIVER: user %s unknown; dropping", user_id)
            return
        if loc["server_id"] == self.server_id:
            async with self.lock:
                ws = self.local_clients.get(user_id)
            if ws:
                try:
                    await ws.send(json.dumps(envelope))
                    logging.info("Delivered SERVER_DELIVER to local user %s", user_id)
                except Exception as e:
                    logging.warning("Failed to deliver to %s: %s", user_id, e)
            else:
                logging.info("User %s absent locally; removing mapping", user_id)
                remove = {"type": "USER_REMOVE", "from": self.server_id, "to": "*", "ts": now_ms(),
                          "payload": {"user_id": user_id, "server_id": self.server_id}}
                remove["sig"] = self.sign_envelope(remove)
                await self._handle_user_remove(remove)
        else:
            await self.send_to_server(loc["server_id"], envelope)
            logging.info("Forwarded SERVER_DELIVER for %s to %s", user_id, loc["server_id"])

    async def _handle_client_register(self, conn: PeerConnection, envelope: Dict[str, Any]):
        if conn.is_server:
            return
        payload = envelope.get("payload", {}) or {}
        user_id = payload.get("user_id") or envelope.get("from")
        if not user_id:
            logging.info("Client register without user_id")
            return
        async with self.lock:
            if user_id in self.local_clients:
                logging.warning("Registration failed — name in use: %s", user_id)
                return
            self.local_clients[user_id] = conn.ws
            self.user_locations[user_id] = {"server_id": self.server_id, "ts": time.time()}
        logging.info("Client registered as %s", user_id)
        adv = {"type": "USER_ADVERTISE", "from": self.server_id, "to": "*", "ts": now_ms(),
               "payload": {"user_id": user_id, "server_id": self.server_id}}
        adv["sig"] = self.sign_envelope(adv)
        await self.broadcast_to_servers(adv)


    # Sending and broadcasting
    async def _send_raw(self, conn: PeerConnection, envelope: Dict[str, Any]):
        try:
            await conn.ws.send(json.dumps(envelope))
            conn.last_sent = time.time()
        except Exception as e:
            logging.warning("Failed to send to %s: %s", conn.remote_id or "client", e)

    async def send_to_server(self, server_id: str, envelope: Dict[str, Any]):
        async with self.lock:
            conn = self.server_peers.get(server_id)
        if conn:
            await self._send_raw(conn, envelope)
            return
        addr = self.server_addrs.get(server_id, {}).get("ws_uri")
        if addr:
            if server_id not in self._reconnect_tasks:
                logging.info("No connection to %s — scheduling reconnect to %s", server_id, addr)
                self._reconnect_tasks[server_id] = asyncio.create_task(self._reconnect_loop(addr, server_id))
        else:
            logging.warning("No route to server %s; dropping envelope", server_id)

    async def broadcast_to_servers(self, envelope: Dict[str, Any], exclude: Optional[list] = None):
        exclude = exclude or []
        async with self.lock:
            peers = list(self.server_peers.items())
        for sid, conn in peers:
            if sid in exclude:
                continue
            await self._send_raw(conn, envelope)


    # Outbound connect and reconnect loop

    async def connect_to_peer(self, uri: str, remote_server_id: Optional[str] = None):
        try:
            ws = await websockets.connect(uri)
            hello = {"type": "SERVER_HELLO_JOIN", "from": self.server_id, "to": "*", "ts": now_ms(),
                     "payload": {"ws_uri": uri}}
            # sign HELLO with this server's secret
            hello["sig"] = self.sign_envelope(hello)
            await ws.send(json.dumps(hello))

            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            msg = json.loads(raw)

            # If the welcome is from a pinned introducer, verify using introducer secret
            sender = msg.get("from")
            if sender in self.introducers:
                ok = self.verify_signature_with_secret(msg, self.introducers[sender])
                if not ok:
                    logging.warning("Received SERVER_WELCOME from pinned introducer %s with invalid sig; closing", sender)
                    await ws.close()
                    return None
                logging.info("Verified SERVER_WELCOME signature from introducer %s", sender)

            # otherwise, if message had sig verify with our model (best-effort)
            else:
                if not self.verify_signature(msg):
                    logging.warning("SERVER_WELCOME signature invalid or missing; rejecting connection to %s", uri)
                    await ws.close()
                    return None

            conn = PeerConnection(ws, is_server=True, remote_id=(msg.get("from") or remote_server_id), uri=uri)
            async with self.lock:
                self.connections[ws] = conn
                if conn.remote_id:
                    self.server_peers[conn.remote_id] = conn
                    self.server_addrs[conn.remote_id] = {"ws_uri": uri}
            # process welcome to merge snapshot
            await self.handle_envelope(conn, msg)

            conn._recv_task = asyncio.create_task(self.receive_loop(conn))
            conn._heartbeat_task = asyncio.create_task(self.heartbeat_loop(conn))
            logging.info("Connected to peer %s at %s", conn.remote_id or uri, uri)
            return conn
        except Exception as e:
            logging.warning("Failed to connect to peer %s: %s", uri, e)
            return None

    async def _reconnect_loop(self, uri: str, expected_server_id: Optional[str] = None):
        delay = RECONNECT_BASE
        key = expected_server_id or uri
        logging.info("Starting reconnect loop to %s (expect id=%s)", uri, expected_server_id)
        try:
            while True:
                if expected_server_id:
                    async with self.lock:
                        if expected_server_id in self.server_peers:
                            logging.info("Already connected to %s; stopping reconnect", expected_server_id)
                            break
                conn = await self.connect_to_peer(uri, remote_server_id=expected_server_id)
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


    # Cleanup and status

    async def cleanup_connection(self, conn: PeerConnection):
        async with self.lock:
            self.connections.pop(conn.ws, None)
            if conn.remote_id and self.server_peers.get(conn.remote_id) is conn:
                del self.server_peers[conn.remote_id]

            to_remove = [uid for uid, ws in self.local_clients.items() if ws is conn.ws]
            for uid in to_remove:
                logging.info("Cleaning up local client %s", uid)
                del self.local_clients[uid]
                if uid in self.user_locations:
                    del self.user_locations[uid]
                remove = {"type": "USER_REMOVE", "from": self.server_id, "to": "*", "ts": now_ms(),
                          "payload": {"user_id": uid, "server_id": self.server_id}}
                remove["sig"] = self.sign_envelope(remove)
                await self.broadcast_to_servers(remove)

    def list_status(self) -> Dict[str, Any]:
        return {
            "known_users": list(self.user_locations.keys()),
            "known_servers": list(self.server_peers.keys()),
            "local_clients": list(self.local_clients.keys()),
            "reconnect_tasks": list(self._reconnect_tasks.keys()),
            "pinned_introducers": list(self.introducers.keys())
        }


# -------------------------
# CLI / main
# -------------------------
def parse_introducers(args_list: List[str]) -> Dict[str, str]:
    """
    Parse introducer tokens like: id=secret
    Accepts a list of such strings.
    """
    out = {}
    for it in args_list or []:
        if "=" in it:
            k, v = it.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k and v:
                out[k] = v
    return out


async def main_loop(host: str, port: int, server_id: str, secret: str, peers: list, introducers: Dict[str, str]):
    if len(introducers) < 3:
        logging.warning("Introducer list has fewer than 3 entries — spec recommends ≥3 pinned introducers for trust root.")
    core = ServerCore(server_id, secret, introducers)

    async def ws_handler(ws, path=None):
        await core.handler(ws, path)

    server = await websockets.serve(ws_handler, host, port)
    logging.info("server listening on %s:%s", host, port)
    logging.info("Server %s listening on %s:%s", server_id, host, port)

    # start outbound reconnect loops for configured peers
    for p in peers or []:
        if p not in core._reconnect_tasks:
            core._reconnect_tasks[p] = asyncio.create_task(core._reconnect_loop(p, expected_server_id=None))

    async def status_printer():
        while True:
            await asyncio.sleep(20)
            st = core.list_status()
            logging.info("Known users: %s", st["known_users"])
            logging.info("Known servers: %s", st["known_servers"])
            logging.info("Local clients: %s", st["local_clients"])
            logging.info("Reconnect tasks: %s", st["reconnect_tasks"])
            logging.info("Pinned introducers: %s", st["pinned_introducers"])

    await status_printer()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--server-id", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--peers", nargs="*", help="Peer websocket URIs to connect to, e.g. ws://127.0.0.1:8766")
    ap.add_argument("--introducers", nargs="*", help="Pinned introducers as id=secret pairs (e.g. i1=s3,i2=s4,i3=s5)")
    args = ap.parse_args()

    introducers = parse_introducers(args.introducers or [])
    try:
        asyncio.run(main_loop(args.host, args.port, args.server_id, args.secret, args.peers or [], introducers))
    except KeyboardInterrupt:
        logging.info("Shutting down")
        try:
            sys.exit(0)
        except SystemExit:
            pass
