import asyncio
from client import Client

if __name__ == "__main__":

    client = Client()
    asyncio.run(client.run_client())
