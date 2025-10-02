
import asyncio
import base64
import pathlib
from crypto_services.base64url import b64url_decode, b64url_encode
from crypto_services.canonical import preimage_dm
from crypto_services.rsa import decrypt_rsa_oaep, encrypt_rsa_oaep, generate_rsa4096_keypair, load_private_key_der, private_key_to_der, public_key_to_b64url, sign_pss_sha256, verify_pss_sha256
from crypto_services.secure_store import get_password_hasher, protect_private_key, recover_private_key
import websockets
import uuid
import protocol
import os



from customised_types import ServerMessageType, CustomisedMessageType, UserAuthType

DM_COMMAND = "/tell "
FILE_COMMAND = "/file "
LIST_COMMAND = "/list"
CLOSE_COMMAND = "/quit"
PUBLIC_COMMAND = "/all "
CHUNK_SIZE=4096


REGISTER_COMMAND = "/register"
LOGIN_COMMAND = "/login "

SERVER_ID="server-1"


class Client():

    def __init__(self):
        self.server_id = "server-1"
        self.user_id = None
        self.der_priv=None
        self.der_pub=None
        self.recv_queue = asyncio.Queue()
        

    async def sender(self, ws):
        loop = asyncio.get_event_loop()
        while True:
            cmd = await loop.run_in_executor(None, input)
            
            
            # Register new user
            if cmd.startswith(REGISTER_COMMAND):
                
                # create new user id
                user_id = str(uuid.uuid4())
                password = input("Create password: ")
                register_msg = register(password=password, user_id=user_id, server_id=self.server_id)
                
                print(f"[REGISTER] Send register request to server for uid {user_id}")
                await ws.send(register_msg)
            

            # Send login request
            elif cmd.startswith(LOGIN_COMMAND):
                
                uid = cmd[len(LOGIN_COMMAND):]
                
                password = input("Enter password: ")


                # Send LOGIN REQUEST
                await ws.send(protocol.make_envelope(
                    msg_type=UserAuthType.LOGIN_REQUEST,
                    from_id=uid, 
                    to_id=self.server_id,
                    payload={
                        "password": password
                    }
                ))

                # Wait for the server response from queue
                while True:
                    response = await self.recv_queue.get()
                    if response.get("type") in [UserAuthType.LOGIN_SUCCESS, UserAuthType.LOGIN_FAIL]:
                        break

                if response["type"] == UserAuthType.LOGIN_SUCCESS:
                    # Send USER_HELLO to join network on login success
                    self.user_id = uid
                    payload = response["payload"]

                    # get derived private key and encoded public key
                    self.der_pub = payload["pubkey"]
                    privkey_store = payload["privkey_store"]
                    decoded_private = b64url_decode(privkey_store)
                    self.der_priv = recover_private_key(blob=decoded_private, password=password)

                    hello = protocol.make_envelope(
                        msg_type="USER_HELLO",
                        from_id=self.user_id,
                        to_id="server-1",
                        payload={
                            "client": "cli-v1", 
                            "pubkey": payload["pubkey"],
                            "enc_pubkey": payload["pubkey"]
                            },
                        sig=""
                    )

                    print(f"[LOGIN SUCCESS] User {uid} login success.")
                    await ws.send(hello)
                else:
                    print(f"[LOGIN FAILED] Failed login attempt for {uid}")
                    continue



                

            # Direct messaging 
            elif cmd.startswith(DM_COMMAND):

                try:
                    _, target, msg = cmd.split(" ", maxsplit=2)
                except ValueError:
                    print("[CLIENT] Usage: /tell <user_id> <message>")
                    continue

                receiver_public = ""
                sender_public = self.der_pub
                sender_private = load_private_key_der(self.der_priv)

                msg = msg.encode("utf-8")
                ciphertext = encrypt_rsa_oaep(msg, receiver_public)
                ciphertext = b64url_encode(ciphertext)
                pm_msg = preimage_dm(ciphertext, "1" ,"2", 1759388690830)

                content_sig = sign_pss_sha256(pm_msg, sender_private)

                # DM plaintext 
                dm = protocol.make_envelope(
                    msg_type="MSG_DIRECT", 
                    from_id=self.user_id, 
                    to_id=target, 
                    payload={
                        "ciphertext": msg,
                        "sender_pub": sender_public,
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
                    from_id=self.user_id, 
                    to_id=target, 
                    payload=manifest))
                

                print(f"[CLIENT:{self.user_id}] Started sending file {name}")

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
                            from_id=self.user_id, 
                            to_id=target, 
                            payload=frame,
                            sig=""))
                        
                        idx += 1

                # FILE_END
                await ws.send(protocol.make_envelope(
                    msg_type="FILE_END", 
                    from_id=self.user_id, 
                    to_id=target, 
                    payload={"file_id": file_id},
                    sig=""))
                

                print(f"[CLIENT:{self.user_id}] Finished sending file {name}")
            
            # PUBLIC CHANNEL CHAT 
            elif cmd.startswith(PUBLIC_COMMAND):
                try:
                    text = cmd[len(PUBLIC_COMMAND):]
                except ValueError:
                    print("[CLIENT] Usage: /all <text>")
                    continue


                msg_public = protocol.make_envelope(
                    msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                    from_id=self.user_id,
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
                    from_id=self.user_id,
                    to_id="server-1",
                    payload={}
                )

                await ws.send(lst_msg)



            # GRACEFUL DISCONNECT REQUEST
            elif cmd.startswith(CLOSE_COMMAND):
                ctrl = protocol.make_envelope(
                    msg_type="CTRL_CLOSE", 
                    from_id=self.user_id, 
                    to_id="server-1", 
                    payload={})
                await ws.send(ctrl)
                await ws.close(code=1000)
                print(f"[CLIENT:{self.user_id}] Disconnected")
                return






    async def receiver(self, ws):

        files_in_progress = {}


        async for raw in ws:
            frame = protocol.parse_envelope(raw)
            await self.recv_queue.put(frame)

                


            if frame["type"] == "USER_DELIVER":
                print(f"DM from {frame['payload'].get('sender')}: {frame['payload'].get('ciphertext')}")

                ciphertext = frame["payload"].get("ciphertext")
                sender_pub = frame["payload"].get("sender_pub")
                content_sig = frame["payload"].get("content_sig")

                private_key = load_private_key_der(self.der_priv)


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
    
        


    async def run_client(self, host="localhost", port=8765): 
        uri = f"ws://{host}:{port}"

        # private_key, public_key = generate_rsa4096_keypair()



        async with websockets.connect(uri) as ws:
            print(f"[CLIENT:{self.user_id}] Connected to {uri}")

    
            await asyncio.gather(self.sender(ws), self.receiver(ws))









def register(user_id: str, password: str, server_id: str):
    # Generate RSA keys
    priv, pub = generate_rsa4096_keypair()
    priv_bytes = private_key_to_der(priv=priv)
    encrypted_priv = protect_private_key(der_priv=priv_bytes, password=password)
    
    # salted password hash
    ph = get_password_hasher()
    salted_hash = ph.hash(password)
    
    
    
    message = protocol.make_envelope(
        msg_type=UserAuthType.REGISTER,
        from_id=user_id,
        to_id=server_id,
        payload={
            "pubkey": public_key_to_b64url(pub=pub),
            "privkey_store": b64url_encode(data=encrypted_priv),
            "pake_password": salted_hash,
        },
        sig=""
    )

    return message


