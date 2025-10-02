import asyncio
from server import Server

if __name__ == "__main__":
    server = Server()
    asyncio.run(server.start_server())
