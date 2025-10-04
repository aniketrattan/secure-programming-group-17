import os
import asyncio
import argparse
import logging
import signal
from urllib.parse import urlparse

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


async def _run(host: str, port: int, server_id: str, peers: list[str]) -> None:
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
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    parser = argparse.ArgumentParser(description="SOCP integration server runner")
    parser.add_argument("--bind", default=os.getenv("BIND", "ws://127.0.0.1:8765"), help="Bind address ws://host:port")
    parser.add_argument("--peer", action="append", help="Peer ws://host:port (repeatable)")
    parser.add_argument("--server-id", default=os.getenv("SERVER_ID", "server-1"), help="Stable server UUID")
    args = parser.parse_args()

    host, port = _parse_bind(args.bind)
    peers = _collect_peers(args.peer)

    asyncio.run(_run(host, port, args.server_id, peers))


if __name__ == "__main__":
    main()


