import asyncio
import websockets
import json
import time
import os

from . import tables
from .protocol import make_envelope, parse_envelope
from .customised_types import ServerMessageType, CustomisedMessageType, UserAuthType
from .database import SecureMessagingDB
from .transport import generate_server_keys, sign_transport_payload
from .crypto_services.secure_store import get_password_hasher
from .crypto_services import (
    b64url_encode,
    b64url_decode,
    encrypt_rsa_oaep,
    sign_pss_sha256,
    verify_pss_sha256,
    load_public_key_b64url,
    preimage_public,
    preimage_file_chunk,
    load_private_key_der,
    preimage_keyshare,
    assert_valid_ts,
)


SERVER_ID = "server-1"  # placeholder UUID
db = SecureMessagingDB()
_SERVER_PRIV_DER, SERVER_PUB_B64 = generate_server_keys()
SERVER_PRIV = load_private_key_der(_SERVER_PRIV_DER)
_PWD_HASHER = get_password_hasher()

# Public channel versioning and wrapped key distribution (RSA-only; key not used for payloads)
PUBLIC_GROUP_VERSION = 1
PUBLIC_GROUP_KEY = os.urandom(32)


async def broadcast_raw(raw: str) -> None:
    # Send to all local users
    for recipient_ws in list(tables.local_users.values()):
        try:
            await recipient_ws.send(raw)
        except Exception:
            pass
    # Forward to peer servers
    for to_server_id, server_ws in list(tables.servers.items()):
        try:
            await server_ws.send(raw)
        except Exception:
            pass


async def send_public_key_share(ws, member_id: str):
    pub_b64 = db.get_pubkey(member_id)
    if not pub_b64:
        return
    member_pub = load_public_key_b64url(pub_b64)
    wrapped = b64url_encode(encrypt_rsa_oaep(PUBLIC_GROUP_KEY, member_pub))
    shares = [{"member": member_id, "wrapped_key": wrapped}]

    ts_ms = int(time.time() * 1000)
    # Sign shares with key-share preimage per SOCP: sha256(canon(shares)) || creator_pub
    pm = preimage_keyshare(shares, SERVER_PUB_B64)
    content_sig = b64url_encode(sign_pss_sha256(pm, SERVER_PRIV))

    # Persist wrapped key for membership semantics
    try:
        db.set_wrapped_public_key(member_id, wrapped, ts_ms)
    except Exception:
        pass

    # Send key-share directly to the member
    await ws.send(make_envelope(
        msg_type=ServerMessageType.PUBLIC_CHANNEL_KEY_SHARE,
        from_id=SERVER_ID,
        to_id=member_id,
        payload={
            "group_id": "public",
            "version": PUBLIC_GROUP_VERSION,
            "shares": shares,
            "creator_pub": SERVER_PUB_B64,
            "content_sig": content_sig,
        },
        sig=sign_transport_payload({"shares": shares}, _SERVER_PRIV_DER),
        ts=ts_ms,
    ))

    # Broadcast updated version notice
    await broadcast_raw(make_envelope(
        msg_type=ServerMessageType.PUBLIC_CHANNEL_UPDATED,
        from_id=SERVER_ID,
        to_id="*",
        payload={"version": PUBLIC_GROUP_VERSION, "added": [member_id]},
        sig=sign_transport_payload({"version": PUBLIC_GROUP_VERSION}, _SERVER_PRIV_DER),
        ts=ts_ms,
    ))


async def rotate_public_group(added: list[str] | None = None, removed: list[str] | None = None):
    global PUBLIC_GROUP_VERSION, PUBLIC_GROUP_KEY
    PUBLIC_GROUP_VERSION += 1
    PUBLIC_GROUP_KEY = os.urandom(32)
    ts_ms = int(time.time() * 1000)
    # Send fresh key-shares to all local users
    for uid, uws in list(tables.local_users.items()):
        try:
            await send_public_key_share(uws, uid)
        except Exception:
            pass
    # Broadcast version bump
    payload = {"version": PUBLIC_GROUP_VERSION}
    if added:
        payload["added"] = added
    if removed:
        payload["removed"] = removed
    await broadcast_raw(make_envelope(
        msg_type=ServerMessageType.PUBLIC_CHANNEL_UPDATED,
        from_id=SERVER_ID,
        to_id="*",
        payload=payload,
        sig=sign_transport_payload({"version": PUBLIC_GROUP_VERSION}, _SERVER_PRIV_DER),
        ts=ts_ms,
    ))


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
                    # Enforce RSA-4096 on ingest; return BAD_KEY if invalid
                    try:
                        load_public_key_b64url(payload["pubkey"])
                    except Exception as exc:
                        err_payload = {"code": "BAD_KEY", "detail": "RSA-4096 required"}
                        await ws.send(make_envelope(
                            msg_type="ERROR",
                            from_id=SERVER_ID,
                            to_id=sender,
                            payload=err_payload,
                            sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER)
                        ))
                        continue
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
                    code = "BAD_KEY" if "RSA-4096" in str(e) else "REGISTER_FAIL"
                    err_payload = {"code": code, "detail": str(e)}
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
                        payload={"code": "NAME_IN_USE", "detail": "User id already existed"},
                        sig=sign_transport_payload({"code": "NAME_IN_USE", "detail": "User id already existed"}, _SERVER_PRIV_DER),
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

                    # Bump version on member join and redistribute (sends key-shares to all including this user)
                    await rotate_public_group(added=[user_id])

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
                    err_payload = {"code": "USER_NOT_FOUND", "detail": f"{recipient} not online"}
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload=err_payload,
                        sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER)
                    ))

            elif msg_type == ServerMessageType.MSG_PUBLIC_CHANNEL:
                sender = frame["from"]
                payload = frame.get("payload", {})
                ts = frame.get("ts", 0)

                # Validate required fields
                sender_pub_b64 = payload.get("sender_pub", "")
                multict = payload.get("multict")
                single_ct = payload.get("ciphertext")

                try:
                    sender_pub = load_public_key_b64url(sender_pub_b64)
                except Exception:
                    sender_pub = None

                # Enforce non-zero timestamp
                try:
                    assert_valid_ts(ts)
                except Exception:
                    err_payload = {"code": "INVALID_SIG", "detail": "bad ts"}
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload=err_payload,
                        sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                        ts=int(time.time() * 1000),
                    ))
                    continue

                if multict:
                    if not (ts and isinstance(multict, list) and sender_pub):
                        err_payload = {"code": "INVALID_SIG", "detail": "missing fields"}
                        await ws.send(make_envelope(
                            msg_type="ERROR",
                            from_id=SERVER_ID,
                            to_id=sender,
                            payload=err_payload,
                            sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                            ts=int(time.time() * 1000),
                        ))
                        continue
                    members = set(db.get_public_members())
                    for item in multict:
                        rid = item.get("to")
                        c = item.get("ciphertext")
                        sig_item = item.get("content_sig", "")
                        if not rid or rid not in members or not c or not sig_item:
                            continue
                        if not verify_pss_sha256(preimage_public(c, sender, ts), b64url_decode(sig_item), sender_pub):
                            continue
                        if rid in tables.local_users:
                            out_payload = {"ciphertext": c, "sender_pub": sender_pub_b64, "content_sig": sig_item}
                            await tables.local_users[rid].send(make_envelope(
                                msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                                from_id=sender,
                                to_id=rid,
                                payload=out_payload,
                                sig=sign_transport_payload(out_payload, _SERVER_PRIV_DER),
                                ts=ts,
                            ))
                    for to_server_id, server_ws in tables.servers.items():
                        if to_server_id != SERVER_ID:
                            await server_ws.send(raw)
                elif single_ct:
                    sig_b64 = payload.get("content_sig", "")
                    if not (ts and sender_pub and sig_b64):
                        err_payload = {"code": "INVALID_SIG", "detail": "missing fields"}
                        await ws.send(make_envelope(
                            msg_type="ERROR",
                            from_id=SERVER_ID,
                            to_id=sender,
                            payload=err_payload,
                            sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                            ts=int(time.time() * 1000),
                        ))
                        continue
                    if not verify_pss_sha256(preimage_public(single_ct, sender, ts), b64url_decode(sig_b64), sender_pub):
                        err_payload = {"code": "INVALID_SIG", "detail": "bad content_sig"}
                        await ws.send(make_envelope(
                            msg_type="ERROR",
                            from_id=SERVER_ID,
                            to_id=sender,
                            payload=err_payload,
                            sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                            ts=int(time.time() * 1000),
                        ))
                        continue
                    # Deliver only to addressed recipient
                    members = set(db.get_public_members())
                    dest = frame.get("to")
                    out_payload = {
                        "ciphertext": single_ct,
                        "sender_pub": sender_pub_b64,
                        "content_sig": sig_b64,
                        "public_version": payload.get("public_version"),
                    }
                    if dest and dest in members:
                        if dest in tables.local_users:
                            await tables.local_users[dest].send(make_envelope(
                                msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL,
                                from_id=sender,
                                to_id=dest,
                                payload=out_payload,
                                sig=sign_transport_payload(out_payload, _SERVER_PRIV_DER),
                                ts=ts,
                            ))
                        elif dest in tables.user_locations and tables.user_locations.get(dest) != "local":
                            # Forward to the owning server only
                            to_server_id = tables.user_locations[dest]
                            await tables.servers[to_server_id].send(raw)
                        else:
                            err_payload = {"code": "USER_NOT_FOUND", "detail": f"{dest} not online"}
                            await ws.send(make_envelope(
                                msg_type="ERROR",
                                from_id=SERVER_ID,
                                to_id=sender,
                                payload=err_payload,
                                sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                                ts=int(time.time() * 1000),
                            ))
                else:
                    err_payload = {"code": "FORMAT", "detail": "missing multict or ciphertext"}
                    await ws.send(make_envelope(
                        msg_type="ERROR",
                        from_id=SERVER_ID,
                        to_id=sender,
                        payload=err_payload,
                        sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                        ts=int(time.time() * 1000),
                    ))

            elif msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
                sender = frame["from"]
                recipient = frame["to"]

                if msg_type == "FILE_CHUNK":
                    p = frame.get("payload", {})
                    ts = frame.get("ts", 0)
                    # Enforce non-zero timestamp
                    try:
                        assert_valid_ts(ts)
                    except Exception:
                        err_payload = {"code": "INVALID_SIG", "detail": "bad ts"}
                        await ws.send(make_envelope(
                            msg_type="ERROR",
                            from_id=SERVER_ID,
                            to_id=sender,
                            payload=err_payload,
                            sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                            ts=int(time.time() * 1000),
                        ))
                        continue
                    try:
                        pm = preimage_file_chunk(
                            p.get("ciphertext", ""), sender, recipient, ts, p.get("file_id", ""), int(p.get("index", 0)), int(p.get("total", 0))
                        )
                        ok = verify_pss_sha256(pm, b64url_decode(p.get("content_sig", "")), load_public_key_b64url(p.get("sender_pub", "")))
                    except Exception:
                        ok = False
                    if not ok:
                        err_payload = {"code": "INVALID_SIG", "detail": "bad file chunk sig"}
                        await ws.send(make_envelope(
                            msg_type="ERROR",
                            from_id=SERVER_ID,
                            to_id=sender,
                            payload=err_payload,
                            sig=sign_transport_payload(err_payload, _SERVER_PRIV_DER),
                            ts=int(time.time() * 1000),
                        ))
                        continue

                if recipient in tables.local_users:
                    out_payload = frame.get("payload", {})
                    await tables.local_users[recipient].send(make_envelope(
                        msg_type=msg_type,
                        from_id=sender,
                        to_id=recipient,
                        payload=out_payload,
                        sig=sign_transport_payload(out_payload, _SERVER_PRIV_DER),
                        ts=frame.get("ts"),
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
            elif msg_type == ServerMessageType.PUBLIC_MEMBERS_SNAPSHOT:
                sender = frame.get("from")
                members = db.get_public_members()
                snapshot = {"members": members, "version": PUBLIC_GROUP_VERSION}
                await ws.send(make_envelope(
                    msg_type=ServerMessageType.PUBLIC_MEMBERS_SNAPSHOT,
                    from_id=SERVER_ID,
                    to_id=sender,
                    payload=snapshot,
                    sig=sign_transport_payload(snapshot, _SERVER_PRIV_DER),
                    ts=int(time.time() * 1000),
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
            # Rotate public group on member removal
            await rotate_public_group(removed=[user_id])


async def start_server(host="localhost", port=8765):
    async with websockets.serve(handle_client, host, port, ping_interval=15, ping_timeout=45):
        # periodic status print (like Ammar's core)
        async def status_loop():
            while True:
                await asyncio.sleep(20)
                print(f"Known users: {list(tables.user_locations.keys())}")
                print(f"Known servers: {list(tables.servers.keys())}")
        await status_loop()


