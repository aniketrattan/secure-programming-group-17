import asyncio
import json
import argparse
import logging
import time
import hmac
import hashlib
import base64
from typing import Dict, Any, Optional
import websockets
from websockets.server import WebSocketServerProtocol

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
    def __init__(self, server_id: str, secret: str):
        self.server_id = server_id
        self.secret = secret.encode()

        # Map websocket -> PeerConnection
        self.connections: Dict[WebSocketServerProtocol, PeerConnection] = {}

        # Map server_id -> PeerConnection (for peer servers)
        self.server_peers: Dict[str, PeerConnection] = {}

        # Map user_id -> (server_id, last_seen_ts)
        self.user_locations: Dict[str, Dict[str, Any]] = {}

        # Local clients: user_id -> ws
        self.local_clients: Dict[str, WebSocketServerProtocol] = {}

        # Lock
        self.lock = asyncio.Lock()

    def sign_envelope(self, envelope: Dict[str, Any]) -> str:
        # HMAC-SHA256 signature over canonical payload
        to_sign = (str(envelope.get('type', '')) +
                   "|" + str(envelope.get('from', '')) +
                   "|" + str(envelope.get('to', '')) +
                   "|" + str(envelope.get('ts', ''))).encode()
        sig = hmac.new(self.secret, to_sign, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def verify_signature(self, envelope: Dict[str, Any]) -> bool:
        sig = envelope.get('sig')
        if not sig:
            return False
        expected = self.sign_envelope(envelope)
        return hmac.compare_digest(expected, sig)

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
        if msg.get('type') not in ('CLIENT_HELLO', 'SERVER_HELLO_JOIN'):
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

        # Respond with SERVER_WELCOME
        welcome = self._make_envelope('SERVER_WELCOME', self.server_id, conn.remote_id, payload={'server_id': self.server_id})
        await self._send_raw(conn, welcome)

        # Send SERVER_ANNOUNCE to all servers announcing presence
        announce = self._make_envelope('SERVER_ANNOUNCE', self.server_id, '*', payload={'server_id': self.server_id})
        await self.broadcast_to_servers(announce, exclude=[conn.remote_id])

        # Share current user_locations snapshot
        async with self.lock:
            snapshot = {'user_locations': self.user_locations}
        snap_msg = self._make_envelope('SERVER_ANNOUNCE', self.server_id, conn.remote_id, payload=snapshot)
        await self._send_raw(conn, snap_msg)

    async def handle_client_join(self, conn: PeerConnection, hello_msg: Dict[str, Any]):
        # For clients, register local id if provided
        user_id = hello_msg.get('payload', {}).get('user_id')
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

        if conn.is_server and not self.verify_signature(envelope):
            logging.warning('Invalid signature from server %s', conn.remote_id)

        if typ == 'HEARTBEAT':
            return
        elif typ == 'USER_ADVERTISE':
            await self._handle_user_advertise(envelope)
        elif typ == 'USER_REMOVE':
            await self._handle_user_remove(envelope)
        elif typ == 'USER_MESSAGE':
            await self._handle_user_message(envelope)
        elif typ == 'SERVER_ANNOUNCE':
            await self._handle_server_announce(conn, envelope)
        elif typ == 'SERVER_WELCOME' or typ == 'CLIENT_WELCOME':
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

    async def _handle_server_announce(self, conn: PeerConnection, envelope: Dict[str, Any]):
        payload = envelope.get('payload', {})
        server_id = payload.get('server_id')
        if server_id and server_id != self.server_id:
            if conn.remote_id is None:
                conn.remote_id = server_id
                async with self.lock:
                    self.server_peers[server_id] = conn
            logging.info('Server announced: %s', server_id)

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
            hello = {'type': 'SERVER_HELLO_JOIN', 'from': self.server_id, 'to': '*', 'ts': int(time.time() * 1000), 'payload': {}}
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


async def main_loop(host: str, port: int, server_id: str, secret: str, peer_uris: list):
    core = ServerCore(server_id, secret)

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
    parser.add_argument('--secret', required=True)
    parser.add_argument('--peers', nargs='*', help='Peer websocket URIs to connect to, e.g. ws://localhost:8766')
    args = parser.parse_args()

    try:
        asyncio.run(main_loop(args.host, args.port, args.server_id, args.secret, args.peers or []))
    except KeyboardInterrupt:
        logging.info('Shutting down')
