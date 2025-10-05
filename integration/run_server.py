import argparse
import asyncio
import json
import logging
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .database import USERNAME_TAKEN, SecureMessagingDB
from .network_protocol_core import main_loop as core_main_loop


def _parse_bind(bind_uri: str) -> tuple[str, int]:
    # Accept ws://host:port or host:port
    if bind_uri.startswith("ws://") or bind_uri.startswith("wss://"):
        p = urlparse(bind_uri)
        host = p.hostname or "127.0.0.1"
        port = p.port or 8765
        return host, int(port)
    # fallback: host:port or :port
    if ":" in bind_uri:
        host, port = bind_uri.split(":", 1)
        host = host or "0.0.0.0"
        return host, int(port)
    # just port
    return "0.0.0.0", int(bind_uri)


def _collect_peers(cli_peers: list[str] | None) -> list[str]:
    env_peers = os.getenv("PEERS", "").strip()
    peers = []
    if env_peers:
        peers.extend([p.strip() for p in env_peers.split(",") if p.strip()])
    if cli_peers:
        peers.extend(cli_peers)
    # de-duplicate, preserve order
    seen = set()
    uniq = []
    for p in peers:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


async def _run(
    host: str,
    port: int,
    server_id: str,
    peers: list[str],
    introducers: list[tuple[str, str, str]],
) -> None:
    # Validate server_id is UUID v4 or 'auto' for introducer assignment
    if server_id.lower() != "auto":
        try:
            import uuid as _uuid

            if str(_uuid.UUID(server_id, version=4)) != server_id:
                raise ValueError
        except Exception:
            raise SystemExit("--server-id must be a UUID v4 or 'auto'")

    # Seed introducers (pins) into DB and add URIs to peers
    try:
        db = SecureMessagingDB()
        for sid, pub, uri in introducers:
            db.upsert_trusted_server(sid, pub, ws_uri=uri)
            if uri not in peers:
                peers.append(uri)
    except Exception:
        pass

    task = asyncio.create_task(core_main_loop(host, port, server_id, peers))

    stop = asyncio.Event()

    def _signal_handler():
        try:
            stop.set()
        except Exception:
            pass

    # Install signal handlers when supported
    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except NotImplementedError:
                # Windows may not support SIGTERM
                pass
    except RuntimeError:
        pass

    logging.info("Starting server %s on %s:%s; peers=%s", server_id, host, port, peers)
    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        logging.info("Server %s shutdown complete", server_id)


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    parser = argparse.ArgumentParser(
        description="SOCP integration server runner (core)"
    )
    parser.add_argument(
        "--bind",
        default=os.getenv("BIND", "ws://127.0.0.1:8765"),
        help="Bind address ws://host:port",
    )
    parser.add_argument(
        "--peer", action="append", help="Peer ws://host:port (repeatable)"
    )
    parser.add_argument(
        "--server-id",
        default=os.getenv("SERVER_ID", "auto"),
        help="Stable server UUID v4 or 'auto' for introducer assignment",
    )
    parser.add_argument(
        "--introducer",
        action="append",
        help="Pinned introducer entry: id=pubkey@ws://host:port (repeatable)",
    )
    parser.add_argument(
        "--http",
        default=os.getenv("HTTP_BIND", "127.0.0.1:8080"),
        help="Bind address for directory HTTP (username claim/resolve). Use host:port or 'off' to disable.",
    )
    args = parser.parse_args()

    httpd = None
    if args.http and args.http.lower() != "off":
        http_host, http_port = _parse_bind(args.http)
        _db = SecureMessagingDB()  # ensures tables exist

        class _DirHandler(BaseHTTPRequestHandler):
            server_version = "SOCP-Directory/1.0"

            def _send(self, code: int, body: dict) -> None:
                data = json.dumps(body, separators=(",", ":")).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                try:
                    from urllib.parse import parse_qs

                    u = urlparse(self.path)
                    qs = parse_qs(u.query)
                    if u.path == "/resolve":
                        username = (qs.get("username") or [""])[0]
                        rec = _db.get_user_by_username(username)
                        if not rec:
                            self._send(404, {"ok": False, "error": "NOT_FOUND"})
                            return
                        self._send(
                            200,
                            {
                                "ok": True,
                                "user_id": rec["user_id"],
                                "pubkey": rec["pubkey"],
                                "meta": rec["meta"],
                            },
                        )
                        return
                    if u.path == "/whois":
                        user_id = (qs.get("user_id") or [""])[0]
                        name = _db.get_username_by_user_id(user_id)
                        if not name:
                            self._send(404, {"ok": False, "error": "NOT_FOUND"})
                            return
                        self._send(200, {"ok": True, "username": name})
                        return
                    self._send(404, {"ok": False, "error": "NO_ROUTE"})
                except Exception:
                    logging.exception("HTTP GET error")
                    self._send(500, {"ok": False, "error": "SERVER_ERROR"})

            def do_POST(self):
                try:
                    if self.path == "/username/claim":
                        l = int(self.headers.get("Content-Length") or "0")
                        body = self.rfile.read(l)
                        payload = json.loads(body.decode("utf-8"))
                        user_id = payload.get("user_id") or ""
                        username = payload.get("username") or ""
                        try:
                            _db.create_username(user_id, username)
                        except ValueError as ve:
                            if str(ve) == USERNAME_TAKEN:
                                self._send(409, {"ok": False, "error": USERNAME_TAKEN})
                                return
                            self._send(400, {"ok": False, "error": str(ve)})
                            return
                        self._send(200, {"ok": True})
                        return
                    self._send(404, {"ok": False, "error": "NO_ROUTE"})
                except Exception:
                    logging.exception("HTTP POST error")
                    self._send(500, {"ok": False, "error": "SERVER_ERROR"})

        httpd = ThreadingHTTPServer((http_host, http_port), _DirHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        logging.info("[DIR] listening on http://%s:%s", http_host, http_port)

    # Parse bind and peers, normalize introducers, then run the core
    host, port = _parse_bind(args.bind)
    peers = _collect_peers(args.peer)
    introducers = []
    for entry in args.introducer or []:
        try:
            sid, rest = entry.split("=", 1)
            pub, uri = rest.split("@", 1)
            introducers.append((sid.strip(), pub.strip(), uri.strip()))
        except Exception:
            logging.warning(
                "Bad --introducer format (expected id=pub@ws://host:port): %s", entry
            )
    try:
        asyncio.run(_run(host, port, args.server_id, peers, introducers))
    finally:
        if httpd:
            try:
                httpd.shutdown()
            except Exception:
                pass


if __name__ == "__main__":
    main()
