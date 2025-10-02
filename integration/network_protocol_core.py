import asyncio
import json
import argparse
import logging
import time
import hashlib
from typing import Dict, Any, Optional
import websockets
from websockets.server import WebSocketServerProtocol
from .transport import generate_server_keys, sign_transport_payload, verify_transport_payload
from .crypto_services.canonical import canonical_payload_bytes

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 45

# Envelope keys: type, from, to, ts, payload, sig

class PeerConnection:
    def __init__(self, ws: WebSocketServerProtocol, is_server: bool, remote_id: Optional[str]):
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

        # Map user_id -> (server_id, last_seen_ts)
        self.user_locations: Dict[str, Dict[str, Any]] = {}

        # Local clients: user_id -> ws
        self.local_clients: Dict[str, WebSocketServerProtocol] = {}

        # Loop suppression (ts|from|to|hash(payload))
        from collections import deque
        self._seen_keys = set()
        self._seen_order = deque(maxlen=2048)

        # Lock
        self.lock = asyncio.Lock()

    def sign_envelope(self, envelope: Dict[str, Any]) -> str:
        payload = envelope.get('payload', {})
        return sign_transport_payload(payload, self._priv_der)

    def verify_signature(self, envelope: Dict[str, Any]) -> bool:
        sig = envelope.get('sig')
        if not sig:
            return False
        sender_id = envelope.get('from')
        pub_b64 = self.server_pubkeys.get(sender_id)
        if not pub_b64:
            return False
        payload = envelope.get('payload', {})
        return verify_transport_payload(payload, sig, pub_b64)

    def _make_seen_key(self, envelope: Dict[str, Any]) -> str:
        ts = envelope.get('ts')
        frm = envelope.get('from')
        to = envelope.get('to')
        payload = envelope.get('payload', {})
        h = hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()
        return f"{ts}|{frm}|{to}|{h}"

    def _dedup_and_mark(self, envelope: Dict[str, Any]) -> bool:
        key = self._make_seen_key(envelope)
        if key in self._seen_keys:
            return True
        self._seen_keys.add(key)
        self._seen_order.append(key)
        if len(self._seen_order) == self._seen_order.maxlen:
            old = self._seen_order.popleft()
            if old in self._seen_keys:
                self._seen_keys.discard(old)
        return False

    async def handler(self, ws: WebSocketServerProtocol, path: str):
        # Wait for an initial HELLO from the connecting peer (client or server)
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
        except Exception as e:
            logging.info('No HELLO received, closing connection: %s', e)
            await ws.close()
            return

        try:
            msg = json.loads(raw)
        except Exception:
            logging.warning('First message not JSON; closing')
            await ws.close()
            return

        # Basic validation
        if msg.get('type') not in ('USER_HELLO', 'SERVER_HELLO_JOIN'):
            logging.warning('Unexpected initial message: %s', msg.get('type'))
            await ws.close()
            return

        is_server = msg['type'] == 'SERVER_HELLO_JOIN'
        remote_id = msg.get('from')

        conn = PeerConnection(ws, is_server=is_server, remote_id=remote_id)
        async with self.lock:
            self.connections[ws] = conn
            if is_server and remote_id:
                self.server_peers[remote_id] = conn

        # Complete handshake
        if is_server:
            await self.handle_server_join(conn, msg)
        else:
            await self.handle_client_join(conn, msg)

        # Launch recv and heartbeat tasks
        conn._recv_task = asyncio.create_task(self.receive_loop(conn))
        conn._heartbeat_task = asyncio.create_task(self.heartbeat_loop(conn))

        # Wait for connection tasks to finish
        try:
            await asyncio.gather(conn._recv_task)
        except asyncio.CancelledError:
            pass
        finally:
            await self.cleanup_connection(conn)

    async def handle_server_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        logging.info('Server joining: %s', conn.remote_id)
        # Capture remote pubkey if provided
        try:
            remote_id = hello_msg.get('from')
            remote_pub = hello_msg.get('payload', {}).get('pubkey')
            if remote_id and remote_pub:
                self.server_pubkeys[remote_id] = remote_pub
        except Exception:
            pass

        # Respond with SERVER_WELCOME (include our pubkey)
        welcome = self._make_envelope('SERVER_WELCOME', self.server_id, conn.remote_id,
                                      payload={'server_id': self.server_id, 'server_pub': self.server_pub_b64})
        await self._send_raw(conn, welcome)

        # Send SERVER_ANNOUNCE to all servers announcing presence (host, port, pubkey)
        announce = self._make_envelope('SERVER_ANNOUNCE', self.server_id, '*',
                                       payload={'server_id': self.server_id, 'host': self.host, 'port': self.port, 'pubkey': self.server_pub_b64})
        await self.broadcast_to_servers(announce, exclude=[conn.remote_id])

        # Share current user_locations snapshot
        async with self.lock:
            snapshot = {'user_locations': self.user_locations}
        snap_msg = self._make_envelope('SERVER_ANNOUNCE', self.server_id, conn.remote_id, payload=snapshot)
        await self._send_raw(conn, snap_msg)

    async def handle_client_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        # USER_HELLO
        user_id = hello_msg.get('payload', {}).get('user_id') or hello_msg.get('from')
        if not user_id:
            logging.info('Client connected without user_id')
        else:
            async with self.lock:
                self.local_clients[user_id] = conn.ws
                self.user_locations[user_id] = {'server_id': self.server_id, 'ts': time.time()}
            # Gossip to peers
            adv = self._make_envelope('USER_ADVERTISE', self.server_id, '*', payload={'user_id': user_id, 'server_id': self.server_id})
            await self.broadcast_to_servers(adv)
            logging.info('Client %s joined locally', user_id)

        # send CLIENT_WELCOME
        welcome = self._make_envelope('CLIENT_WELCOME', self.server_id, user_id or 'unknown', payload={'server_id': self.server_id})
        await self._send_raw(conn, welcome)

    def _make_envelope(self, typ: str, from_id: str, to_id: str, payload: Any = None) -> Dict[str, Any]:
        envelope = {
            'type': typ,
            'from': from_id,
            'to': to_id,
            'ts': int(time.time() * 1000),  # milliseconds
            'payload': payload or {}
        }
        envelope['sig'] = self.sign_envelope(envelope)
        return envelope

    async def _send_raw(self, conn: PeerConnection, envelope: Dict[str, Any]):
        try:
            await conn.ws.send(json.dumps(envelope))
            conn.last_sent_heartbeat = time.time()
        except Exception as e:
            logging.warning('Failed to send to %s: %s', conn.remote_id or 'client', e)

    async def send_to_server(self, server_id: str, envelope: Dict[str, Any]):
        async with self.lock:
            conn = self.server_peers.get(server_id)
        if conn:
            await self._send_raw(conn, envelope)
        else:
            logging.warning('No connection to server %s', server_id)

    async def broadcast_to_servers(self, envelope: Dict[str, Any], exclude: Optional[list] = None):
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
                    hb = self._make_envelope('HEARTBEAT', self.server_id, conn.remote_id or '*', payload={'now': int(now)})
                    await self._send_raw(conn, hb)
                if now - conn.last_recv > HEARTBEAT_TIMEOUT:
                    logging.warning('Connection timed out: %s', conn.remote_id or 'client')
                    await conn.close()
                    break
                await asyncio.sleep(HEARTBEAT_INTERVAL / 3)
        except asyncio.CancelledError:
            pass

    async def receive_loop(self, conn: PeerConnection):
        ws = conn.ws
        try:
            async for raw in ws:
                try:
                    envelope = json.loads(raw)
                except Exception:
                    logging.debug('Received non-json, ignoring')
                    continue

                conn.touch()
                await self.handle_envelope(conn, envelope)
        except websockets.exceptions.ConnectionClosed:
            logging.info('Connection closed: %s', conn.remote_id or 'client')
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.exception('Error in receive loop: %s', e)

    async def handle_envelope(self, conn: PeerConnection, envelope: Dict[str, Any]):
        typ = envelope.get('type')

        # Loop suppression
        if self._dedup_and_mark(envelope):
            return

        # Signature verification for server frames except early handshake/announce
        if conn.is_server and typ not in ('HEARTBEAT', 'SERVER_HELLO_JOIN', 'SERVER_WELCOME', 'SERVER_ANNOUNCE'):
            if not self.verify_signature(envelope):
                logging.warning('Invalid signature from server %s', conn.remote_id)
                return

        if typ == 'HEARTBEAT':
            return
        elif typ == 'USER_ADVERTISE':
            await self._handle_user_advertise(envelope)
        elif typ == 'USER_REMOVE':
            await self._handle_user_remove(envelope)
        elif typ == 'USER_MESSAGE':
            await self._handle_user_message(envelope)
        elif typ == 'SERVER_DELIVER':
            await self._handle_server_deliver(envelope)
        elif typ == 'SERVER_ANNOUNCE':
            await self._handle_server_announce(conn, envelope)
        elif typ == 'SERVER_WELCOME':
            # Learn pubkey and remote id
            payload = envelope.get('payload', {})
            remote_pub = payload.get('server_pub')
            frm = envelope.get('from')
            if frm and remote_pub:
                self.server_pubkeys[frm] = remote_pub
            logging.info('Received welcome from %s', frm)
        elif typ == 'CLIENT_WELCOME':
            logging.info('Received welcome: %s', typ)
        elif typ == 'CLIENT_REGISTER':
            await self._handle_client_register(conn, envelope)
        else:
            logging.info('Unhandled envelope type: %s', typ)

    async def _handle_user_advertise(self, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        user_id = payload.get('user_id')
        server_id = payload.get('server_id')
        if not user_id or not server_id:
            return
        async with self.lock:
            self.user_locations[user_id] = {'server_id': server_id, 'ts': time.time()}
        logging.info('User advertised: %s @ %s', user_id, server_id)
        await self.broadcast_to_servers(envelope)

    async def _handle_user_remove(self, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        user_id = payload.get('user_id')
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
        logging.info('User removed: %s', user_id)
        await self.broadcast_to_servers(envelope)

    async def _handle_user_message(self, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        to_user = envelope.get('to') or payload.get('to_user')
        if not to_user:
            logging.debug('User_message without recipient')
            return

        async with self.lock:
            loc = self.user_locations.get(to_user)
        if loc is None:
            logging.info('User %s unknown, cannot route', to_user)
            return
        if loc['server_id'] == self.server_id:
            async with self.lock:
                ws = self.local_clients.get(to_user)
            if ws:
                try:
                    await ws.send(json.dumps(envelope))
                    logging.info('Delivered message to local user %s', to_user)
                except Exception as e:
                    logging.warning('Failed to deliver to local user %s: %s', to_user, e)
            else:
                logging.info('Local user %s not connected, removing', to_user)
                remove = self._make_envelope('USER_REMOVE', self.server_id, '*', payload={'user_id': to_user})
                await self._handle_user_remove(remove)
        else:
            dest_server = loc['server_id']
            await self.send_to_server(dest_server, envelope)
            logging.info('Forwarded message to server %s for user %s', dest_server, to_user)

    async def _handle_server_deliver(self, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        user_id = payload.get('user_id')
        if not user_id:
            return
        async with self.lock:
            loc = self.user_locations.get(user_id)
        if loc is None:
            logging.info('SERVER_DELIVER target %s unknown', user_id)
            return
        if loc['server_id'] == self.server_id:
            # Deliver to local user
            async with self.lock:
                ws = self.local_clients.get(user_id)
            if ws:
                deliver_payload = {
                    'ciphertext': payload.get('ciphertext', ''),
                    'sender': payload.get('sender'),
                    'sender_pub': payload.get('sender_pub', ''),
                    'content_sig': payload.get('content_sig', '')
                }
                out = {
                    'type': 'USER_DELIVER',
                    'from': self.server_id,
                    'to': user_id,
                    'ts': payload.get('orig_ts') or int(time.time() * 1000),
                    'payload': deliver_payload
                }
                out['sig'] = self.sign_envelope(out)
                try:
                    await ws.send(json.dumps(out))
                    logging.info('Delivered SERVER_DELIVER to local user %s', user_id)
                except Exception:
                    logging.warning('Failed to deliver to local user %s', user_id)
        else:
            # Forward unchanged to the correct server
            dest_server = loc['server_id']
            await self.send_to_server(dest_server, envelope)
            logging.info('Forwarded SERVER_DELIVER to server %s for user %s', dest_server, user_id)

    async def _handle_server_announce(self, conn: PeerConnection, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        server_id = payload.get('server_id')
        if server_id and server_id != self.server_id:
            if conn.remote_id is None:
                conn.remote_id = server_id
                async with self.lock:
                    self.server_peers[server_id] = conn
            logging.info('Server announced: %s', server_id)

        # Learn pubkey if present
        if server_id and payload.get('pubkey'):
            self.server_pubkeys[server_id] = payload['pubkey']

        if 'user_locations' in payload:
            snap = payload['user_locations']
            async with self.lock:
                for uid, info in snap.items():
                    existing = self.user_locations.get(uid)
                    if not existing or info.get('ts', 0) > existing.get('ts', 0):
                        self.user_locations[uid] = info
            logging.info('Merged user_locations snapshot from %s', server_id)

        await self.broadcast_to_servers(envelope, exclude=[conn.remote_id])

    async def _handle_client_register(self, conn: PeerConnection, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        user_id = payload.get('user_id')
        if not user_id:
            return
        async with self.lock:
            self.local_clients[user_id] = conn.ws
            self.user_locations[user_id] = {'server_id': self.server_id, 'ts': time.time()}
        logging.info('Client registered as %s', user_id)
        adv = self._make_envelope('USER_ADVERTISE', self.server_id, '*', payload={'user_id': user_id, 'server_id': self.server_id})
        await self.broadcast_to_servers(adv)

    async def cleanup_connection(self, conn: PeerConnection):
        async with self.lock:
            if conn.ws in self.connections:
                del self.connections[conn.ws]
            if conn.remote_id and conn.remote_id in self.server_peers and self.server_peers[conn.remote_id] is conn:
                del self.server_peers[conn.remote_id]

            to_remove = [uid for uid, ws in self.local_clients.items() if ws is conn.ws]
            for uid in to_remove:
                logging.info('Cleaning up local client %s', uid)
                del self.local_clients[uid]
                if uid in self.user_locations:
                    del self.user_locations[uid]
                remove = self._make_envelope('USER_REMOVE', self.server_id, '*', payload={'user_id': uid})
                await self.broadcast_to_servers(remove)

    async def connect_to_peer(self, uri: str, remote_server_id: Optional[str] = None):
        try:
            ws = await websockets.connect(uri)
            hello = {'type': 'SERVER_HELLO_JOIN', 'from': self.server_id, 'to': '*', 'ts': int(time.time() * 1000),
                     'payload': {'host': self.host, 'port': self.port, 'pubkey': self.server_pub_b64}}
            hello['sig'] = self.sign_envelope(hello)
            await ws.send(json.dumps(hello))

            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = json.loads(raw)

            conn = PeerConnection(ws, is_server=True, remote_id=remote_server_id)
            async with self.lock:
                self.connections[ws] = conn
                if remote_server_id:
                    self.server_peers[remote_server_id] = conn
            conn._recv_task = asyncio.create_task(self.receive_loop(conn))
            conn._heartbeat_task = asyncio.create_task(self.heartbeat_loop(conn))
            logging.info('Connected to peer %s', uri)
            return conn
        except Exception as e:
            logging.exception('Failed to connect to peer %s: %s', uri, e)
            return None


async def main_loop(host: str, port: int, server_id: str, peer_uris: list):
    core = ServerCore(server_id, host, port)

    async def ws_handler(ws, path):
        await core.handler(ws, path)

    server = await websockets.serve(ws_handler, host, port)
    logging.info('Server %s listening on %s:%s', server_id, host, port)

    for p in peer_uris:
        asyncio.create_task(core.connect_to_peer(p))

    async def status_printer():
        while True:
            await asyncio.sleep(20)
            async with core.lock:
                logging.info('Known users: %s', list(core.user_locations.keys()))
                logging.info('Known servers: %s', list(core.server_peers.keys()))

    await status_printer()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--server-id', required=True)
    # secret removed; RSA-PSS transport used
    parser.add_argument('--peers', nargs='*', help='Peer websocket URIs to connect to, e.g. ws://localhost:8766')
    args = parser.parse_args()

    try:
        asyncio.run(main_loop(args.host, args.port, args.server_id, args.peers or []))
    except KeyboardInterrupt:
        logging.info('Shutting down')


