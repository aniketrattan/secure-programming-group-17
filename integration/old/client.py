
import asyncio
import base64
import pathlib
from crypto_services.base64url import b64url_decode, b64url_encode
from crypto_services.canonical import preimage_dm
from crypto_services.rsa import decrypt_rsa_oaep, encrypt_rsa_oaep, generate_rsa4096_keypair, sign_pss_sha256, verify_pss_sha256
import websockets
import uuid
import protocol
import os



from customised_types import ServerMessageType, CustomisedMessageType

DM_COMMAND = "/tell "
FILE_COMMAND = "/file "
LIST_COMMAND = "/list"
CLOSE_COMMAND = "/quit"
PUBLIC_COMMAND = "/all "
CHUNK_SIZE=4096


# TODO: make private/public key an attribute
# storing in encoded, decode when fetching 



private_key, public_key = "", ""
    


class Client():

    def __init__(self):
        self.__private_key, self.public_key = generate_rsa4096_keypair()

    async def sender(self, ws, user_id):
        loop = asyncio.get_event_loop()
        while True:
            cmd = await loop.run_in_executor(None, input)
            
            
            # Direct messaging 
            if cmd.startswith(DM_COMMAND):

                try:
                    _, target, msg = cmd.split(" ", maxsplit=2)
                except ValueError:
                    print("[CLIENT] Usage: /tell <user_id> <message>")
                    continue

                receiver_public = ""
                sender_public = ""
                sender_private = ""

                # ciphertext = encrypt_rsa_oaep(msg, receiver_public)
                # ciphertext = b64url_encode(ciphertext)

                # content_sig = sign_pss_sha256(ciphertext, sender_private)


                # msg = msg.encode("utf-8")
                # ciphertext = encrypt_rsa_oaep(msg, receiver_public)
                # ciphertext = b64url_encode(ciphertext)
                # pm_msg = preimage_dm(ciphertext, "1" ,"2", 1759388690830)

                # content_sig = sign_pss_sha256(pm_msg, sender_private)

                # DM plaintext 
                dm = protocol.make_envelope(
                    msg_type="MSG_DIRECT", 
                    from_id=user_id, 
                    to_id=target, 
                    payload={
                        "ciphertext": msg,
                        "sender_pub": "sender_pub",
                        "content_sig": "content_sig"
                    },
                    sig="")
                await ws.send(dm)

            

            # File transfer
            elif cmd.startswith(FILE_COMMAND):
                try:
                    _, target, filepath = cmd.split(" ", 2)
                except ValueError:
                    print("[CLIENT] Usage: /file <user_id> <path>")
                    continue
                

                if not os.path.exists(filepath):
                    print(f"[CLIENT] File not found: {filepath}")
                    continue
                    
                
                # Get file metadata 
                file_id = str(uuid.uuid4())
                size = os.path.getsize(filepath)
                name = os.path.basename(filepath)


                # FILE_START
                manifest = {
                    "file_id": file_id,
                    "name": name,
                    "size": size,
                    "sha256": "demo",
                    "mode": "dm"
                }


                await ws.send(protocol.make_envelope(
                    msg_type="FILE_START", 
                    from_id=user_id, 
                    to_id=target, 
                    payload=manifest))
                

                print(f"[CLIENT:{user_id}] Started sending file {name}")

                # FILE_CHUNK (simple base64 encoding)
                with open(filepath, "rb") as f:
                    idx = 0
                    while chunk := f.read(CHUNK_SIZE):
                        frame = {
                            "file_id": file_id,
                            "index": idx,
                            "ciphertext": b64url_encode(chunk)
                        }
                        await ws.send(protocol.make_envelope(
                            msg_type="FILE_CHUNK", 
                            from_id=user_id, 
                            to_id=target, 
                            payload=frame,
                            sig=""))
                        
                        idx += 1

                # FILE_END
                await ws.send(protocol.make_envelope(
                    msg_type="FILE_END", 
                    from_id=user_id, 
                    to_id=target, 
                    payload={"file_id": file_id},
                    sig=""))
                

                print(f"[CLIENT:{user_id}] Finished sending file {name}")
            
            # PUBLIC CHANNEL CHAT 
            elif cmd.startswith(PUBLIC_COMMAND):
                try:
                    text = cmd[len(PUBLIC_COMMAND):]
                except ValueError:
                    print("[CLIENT] Usage: /all <text>")
                    continue


                msg_public = protocol.make_envelope(
                    msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                    from_id=user_id,
                    to_id="public",
                    payload={
                        "ciphertext": text,
                        "sender_pub": "demo_pub",
                        "content_sig": "demo_sig"
                    },
                    sig=""
                )

                await ws.send(msg_public)


            elif cmd.startswith(LIST_COMMAND):
                lst_msg = protocol.make_envelope(
                    msg_type="LIST_REQUEST",
                    from_id=user_id,
                    to_id="server-1",
                    payload={}
                )

                await ws.send(lst_msg)



            # GRACEFUL DISCONNECT REQUEST
            elif cmd.startswith(CLOSE_COMMAND):
                ctrl = protocol.make_envelope(
                    msg_type="CTRL_CLOSE", 
                    from_id=user_id, 
                    to_id="server-1", 
                    payload={})
                await ws.send(ctrl)
                await ws.close(code=1000)
                print(f"[CLIENT:{user_id}] Disconnected")
                return






    async def receiver(self, ws):

        files_in_progress = {}


        async for raw in ws:
            frame = protocol.parse_envelope(raw)
            if frame["type"] == "USER_DELIVER":
                print(f"DM from {frame['payload'].get('sender')}: {frame['payload'].get('ciphertext')}")

                ciphertext = frame["payload"].get("ciphertext")
                sender_pub = frame["payload"].get("sender_pub")
                content_sig = frame["payload"].get("content_sig")

                private_key = "" # TODO: fetch from database


                # pm_rec = preimage_dm(ciphertext, "1", "2", 1759388690830)
                # # verify content  
                # if verify_pss_sha256(pm_rec, content_sig, sender_pub):

                #     # decode and decrypt
                #     plaintext = decrypt_rsa_oaep(b64url_decode(ciphertext), private_key)
                #     text = plaintext.decode('utf-8')

                #     print(f"Decrypted: {text}")


                # # verify content  
                # if verify_pss_sha256(ciphertext, content_sig, sender_pub):

                #     # decode and decrypt
                #     plaintext = decrypt_rsa_oaep(b64url_decode(ciphertext), private_key)
                    
                #     print(f"DM from {frame['payload'].get('sender')}: {plaintext}")

            
            

            elif frame["type"] == ServerMessageType.MSG_PUBLIC_CHANNEL:
                print(f"[Public] {frame['payload'].get('ciphertext')}")
            
            elif frame["type"] == "FILE_START":
                payload = frame["payload"]
                print(f"Receiving file {payload['name']} ({payload['size']} bytes)")
                files_in_progress[payload["file_id"]] = []

            elif frame["type"] == "FILE_CHUNK":

                # insert at index
                chunk = frame["payload"]
                idx = int(chunk["index"])
                files_in_progress[chunk["file_id"]].insert(idx, base64.b64decode(chunk["ciphertext"]))

            elif frame["type"] == "FILE_END":
                fid = frame["payload"]["file_id"]
                data = b"".join(files_in_progress[fid])
                outpath = pathlib.Path(f"received_file_{fid}")
                outpath.write_bytes(data)
                print(f"File received and saved to {outpath}")
                del files_in_progress[fid]
            
            elif frame["type"] == CustomisedMessageType.LIST_RESPONSE:
                online_users = frame["payload"]["online_users"]

                print(f"Online users: {online_users}")
            
            elif frame["type"] == "ERROR":
                print(f"[ERROR] {frame["payload"]}")
            else:
                pass

        




    async def run_client(self, user_id=None, host="localhost", port=8765):
        if not user_id:
            user_id = str(uuid.uuid4())  # User UUIDv4
        uri = f"ws://{host}:{port}"

        # private_key, public_key = generate_rsa4096_keypair()



        async with websockets.connect(uri) as ws:
            print(f"[CLIENT:{user_id}] Connected to {uri}")

            # Send USER_HELLO
            hello = protocol.make_envelope(
                "USER_HELLO",
                from_id=user_id,
                to_id="server-1",
                payload={"client": "cli-v1", "pubkey": "demo-pub", "enc_pubkey": "demo-pub"},
                sig=""
            )
            await ws.send(hello)

            # TODO: retry mechanism

            await asyncio.gather(self.sender(ws, user_id), self.receiver(ws))
