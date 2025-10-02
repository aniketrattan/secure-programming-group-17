import asyncio
import websockets
import json
import time

from . import tables
from .protocol import make_envelope, parse_envelope
from .customised_types import ServerMessageType, CustomisedMessageType, UserAuthType
from .database import SecureMessagingDB
from .transport import generate_server_keys, sign_transport_payload
from .crypto_services.secure_store import get_password_hasher


SERVER_ID = "server-1"  # placeholder UUID
db = SecureMessagingDB()
_SERVER_PRIV_DER, SERVER_PUB_B64 = generate_server_keys()
_PWD_HASHER = get_password_hasher()


async def handle_client(ws):
    user_id = None
    try:
        async for raw in ws:
            frame = parse_envelope(raw)
            if not frame:
                continue

            msg_type = frame.get("type")

            # --- Auth: Register new user ---
            if msg_type == UserAuthType.REGISTER:
                sender = frame.get("from")
                payload = frame.get("payload", {})
                try:
                    db.register_user(
                        user_id=sender,
                        pubkey=payload["pubkey"],
                        privkey_store=payload["privkey_store"],
                        pake_password=payload["pake_password"],
                        meta={}
                    )
                    ack_payload = {"msg_ref": "REGISTER_OK"}
                    await ws.send(make_envelope(
                        msg_type="ACK",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload=ack_payload,
                        sig=sign_transport_payload(ack_payload, _SERVER_PRIV_DER)
                    ))
                except Exception as e:
                    err_payload = {"code": "REGISTER_FAIL", "detail": str(e)}
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload=err_payload,
                        sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER)
                    ))
                continue

            if msg_type == "USER_HELLO":
                user_id = frame["from"]
                if user_id in tables.local_users:
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=user_id,
                        payload={"code": "NAME_IN_USE", "detail": "User id already existed"}
                    ))
                else:
                    tables.local_users[user_id] = ws
                    tables.user_locations[user_id] = "local"
                    # Optionally use payload, but do not re-register here
                    payload = frame.get("payload", {})
                    db.update_presence(user_id, "online")
                    # Add to public channel and announce
                    db.add_member_to_public(user_id)
                    add_payload = {"add": [db.get_display_name(user_id)], "if_version": 1}
                    # Fan-out to peer servers
                    for to_server_id, server_ws in tables.servers.items():
                        await server_ws.send(make_envelope(
                            msg_type=ServerMessageType.PUBLIC_CHANNEL_ADD,
                            from_id=SERVER_ID,
                            to_id=to_server_id,
                            payload=add_payload,
                            sig=sign_transport_payload(add_payload, _SERVER_PRIV_DER)
                        ))
                    ack_payload = {"msg_ref": "USER_HELLO_OK", "server_pub": SERVER_PUB_B64}
                    await ws.send(make_envelope(
                        msg_type="ACK",
                        from_id=SERVER_ID,
                        to_id=user_id,
                        payload=ack_payload,
                        sig=sign_transport_payload(ack_payload, _SERVER_PRIV_DER)
                    ))

                    # USER_ADVERTISE (stub fanout)
                    for target_server, server_ws in tables.servers.items():
                        await server_ws.send(make_envelope(
                            msg_type=ServerMessageType.USER_ADVERTISE,
                            from_id=SERVER_ID,
                            to_id=target_server,
                            payload={"user_id": user_id, "server_id": SERVER_ID, "meta": {}}
                        ))

            elif msg_type == UserAuthType.LOGIN_REQUEST:
                uid = frame.get("from")
                password = (frame.get("payload", {}) or {}).get("password", "")
                auth = db.get_user_auth(uid)
                if not auth:
                    fail_payload = {"code": "NO_USER", "detail": "Unknown user"}
                    await ws.send(make_envelope(
                        msg_type=UserAuthType.LOGIN_FAIL,
                        from_id=SERVER_ID,
                        to_id=uid,
                        payload=fail_payload,
                        sig=sign_transport_payload(fail_payload, _SERVER_PRIV_DER)
                    ))
                    continue
                try:
                    if _PWD_HASHER.verify(auth["pake_password"], password):
                        ok_payload = {
                            "pubkey": auth["pubkey"],
                            "privkey_store": auth["privkey_store"],
                            "version": auth["version"],
                        }
                        await ws.send(make_envelope(
                            msg_type=UserAuthType.LOGIN_SUCCESS,
                            from_id=SERVER_ID,
                            to_id=uid,
                            payload=ok_payload,
                            sig=sign_transport_payload(ok_payload, _SERVER_PRIV_DER)
                        ))
                    else:
                        raise Exception("Invalid password")
                except Exception:
                    fail_payload = {"code": "BAD_PASSWORD", "detail": "Invalid credentials"}
                    await ws.send(make_envelope(
                        msg_type=UserAuthType.LOGIN_FAIL,
                        from_id=SERVER_ID,
                        to_id=uid,
                        payload=fail_payload,
                        sig=sign_transport_payload(fail_payload, _SERVER_PRIV_DER)
                    ))
                continue

            elif msg_type == "MSG_DIRECT":
                sender = frame["from"]
                recipient = frame["to"]
                payload = frame.get("payload", {})
                orig_ts = frame.get("ts")

                if recipient in tables.local_users:
                    new_payload = {
                        "ciphertext": payload.get("ciphertext", ""),
                        "sender": sender,
                        "sender_pub": payload.get("sender_pub", ""),
                        "content_sig": payload.get("content_sig", "")
                    }
                    await tables.local_users[recipient].send(make_envelope(
                        msg_type="USER_DELIVER",
                        from_id=SERVER_ID,
                        to_id=recipient,
                        payload=new_payload,
                        sig=sign_transport_payload(new_payload, _SERVER_PRIV_DER),
                        ts=orig_ts
                    ))
                elif recipient in tables.user_locations and tables.user_locations.get(recipient) != "local":
                    to_server_id = tables.user_locations[recipient]
                    server_ws = tables.servers[to_server_id]
                    srv_payload = {
                            "user_id": recipient,
                            "ciphertext": payload.get("ciphertext", ""),
                            "sender": sender,
                            "sender_pub": payload.get("sender_pub", ""),
                            "content_sig": payload.get("content_sig", ""),
                            "orig_ts": orig_ts
                        }
                    await server_ws.send(make_envelope(
                        msg_type=ServerMessageType.SERVER_DELIVER,
                        from_id=SERVER_ID,
                        to_id=to_server_id,
                        payload=srv_payload,
                        sig=sign_transport_payload(srv_payload, _SERVER_PRIV_DER)
                    ))
                else:
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload={"code": "USER_NOT_FOUND", "detail": f"{recipient} not online"}
                    ))

            elif msg_type == ServerMessageType.MSG_PUBLIC_CHANNEL:
                sender = frame["from"]
                group_id = frame["to"]
                payload = frame.get("payload", {})

                members = set(db.get_public_members())
                for member_id in list(tables.local_users.keys()):
                    if member_id == sender or member_id not in members:
                        continue
                    out_payload = payload
                    await tables.local_users[member_id].send(make_envelope(
                        msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                        from_id=sender,
                        to_id=group_id,
                        payload=out_payload,
                        sig=sign_transport_payload(out_payload, _SERVER_PRIV_DER)
                    ))

                if sender in tables.local_users:
                    for to_server_id, server_ws in tables.servers.items():
                        if to_server_id != SERVER_ID:
                            await server_ws.send(raw)

            elif msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
                sender = frame["from"]
                recipient = frame["to"]

                if recipient in tables.local_users:
                    out_payload = frame.get("payload", {})
                    await tables.local_users[recipient].send(make_envelope(
                        msg_type=msg_type,
                        from_id=sender,
                        to_id=recipient,
                        payload=out_payload,
                        sig=sign_transport_payload(out_payload, _SERVER_PRIV_DER)
                    ))
                elif recipient in tables.user_locations and tables.user_locations.get(recipient) != "local":
                    # Forward (no wrap)
                    to_server_id = tables.user_locations[recipient]
                    await tables.servers[to_server_id].send(raw)
                else:
                    err_payload = {"code": "USER_NOT_FOUND", "detail": f"{recipient} not online"}
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload=err_payload,
                        sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER)
                    ))

            elif msg_type == CustomisedMessageType.LIST_REQUEST:
                sender = frame["from"]
                list_payload = {"online_users": sorted(tables.user_locations.keys())}
                await ws.send(make_envelope(
                    msg_type=CustomisedMessageType.LIST_RESPONSE,
                    from_id=SERVER_ID,
                    to_id=sender,
                    payload=list_payload,
                    sig=sign_transport_payload(list_payload, _SERVER_PRIV_DER)
                ))
            elif msg_type == ServerMessageType.PUBLIC_CHANNEL_ADD:
                add = frame.get("payload", {}).get("add", [])
                print(f"[SERVER] PUBLIC_CHANNEL_ADD: {add}")
            elif msg_type == ServerMessageType.PUBLIC_CHANNEL_UPDATED:
                remove = frame.get("payload", {}).get("remove", [])
                print(f"[SERVER] PUBLIC_CHANNEL_UPDATED remove: {remove}")
            elif msg_type == "PUBKEY_REQUEST":
                # Return recipient's pubkey for E2EE
                target = frame.get("payload", {}).get("user_id")
                pub = db.get_pubkey(target) if target else None
                resp_payload = {"user_id": target, "pubkey": pub}
                await ws.send(make_envelope(
                    msg_type="PUBKEY_RESPONSE",
                    from_id=SERVER_ID,
                    to_id=frame.get("from"),
                    payload=resp_payload,
                    sig=sign_transport_payload(resp_payload, _SERVER_PRIV_DER)
                ))
            else:
                # ignore unknown
                pass

    except (websockets.exceptions.ConnectionClosedOK, websockets.exceptions.ConnectionClosedError):
        pass
    finally:
        if user_id:
            tables.local_users.pop(user_id, None)
            tables.user_locations.pop(user_id, None)
            db.update_presence(user_id, "offline")
            # Remove from public channel and announce removal
            db.remove_member_from_public(user_id)
            # USER_REMOVE gossip
            rm_payload = {"user_id": user_id}
            for to_server_id, server_ws in tables.servers.items():
                await server_ws.send(make_envelope(
                    msg_type=ServerMessageType.USER_ADVERTISE if False else "USER_REMOVE",
                    from_id=SERVER_ID,
                    to_id=to_server_id,
                    payload=rm_payload,
                    sig=sign_transport_payload(rm_payload, _SERVER_PRIV_DER)
                ))
            # PUBLIC_CHANNEL_UPDATED remove notice
            upd_payload = {"remove": [db.get_display_name(user_id)], "if_version": 1}
            for to_server_id, server_ws in tables.servers.items():
                await server_ws.send(make_envelope(
                    msg_type=ServerMessageType.PUBLIC_CHANNEL_UPDATED,
                    from_id=SERVER_ID,
                    to_id=to_server_id,
                    payload=upd_payload,
                    sig=sign_transport_payload(upd_payload, _SERVER_PRIV_DER)
                ))


async def start_server(host="localhost", port=8765):
    async with websockets.serve(handle_client, host, port, ping_interval=15, ping_timeout=45):
        # periodic status print (like Ammar's core)
        async def status_loop():
            while True:
                await asyncio.sleep(20)
                print(f"Known users: {list(tables.user_locations.keys())}")
                print(f"Known servers: {list(tables.servers.keys())}")
        await status_loop()


