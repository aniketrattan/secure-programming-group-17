import os
import argparse
import asyncio
from .client import Client


def _parse_server(uri_or_host: str | None, port: int | None) -> tuple[str, int]:
    if uri_or_host and uri_or_host.startswith("ws://"):
        from urllib.parse import urlparse
        p = urlparse(uri_or_host)
        return (p.hostname or "127.0.0.1", int(p.port or (port or 1234)))
    host = uri_or_host or os.getenv("CLIENT_HOST", "127.0.0.1")
    return (host, int(port or int(os.getenv("CLIENT_PORT", "1234"))))


def main():
    ap = argparse.ArgumentParser(description="SOCP client runner")
    ap.add_argument("--server", help="ws://host:port of server")
    ap.add_argument("--host", help="Server host (if --server not given)")
    ap.add_argument("--port", type=int, help="Server port (default 1234)")
    args = ap.parse_args()

    host, port = _parse_server(args.server, args.port if args.port else (args.port))
    client = Client()
    asyncio.run(client.run_client(host=host, port=port))


if __name__ == "__main__":
    main()


