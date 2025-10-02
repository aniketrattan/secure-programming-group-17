import asyncio
import websockets
import protocol, tables
import db
from customised_types import ServerMessageType, CustomisedMessageType


SERVER_ID = "server-1"  # TODO: should be UUIDv4

def extract_server_id(to_server):
    prefix = "server_"
    return to_server[len(prefix):]


def remove_user(user_id):
    tables.local_users.pop(user_id)
    tables.user_locations.pop(user_id)


async def handle_client(ws):
    """Handle messages from a connected user (spec §9)"""
    user_id = None
    try:
        async for raw in ws:
            frame = protocol.parse_envelope(raw)
            if not frame:
                continue

            msg_type = frame.get("type")

            # Handle user hello
            if msg_type == "USER_HELLO":
                user_id = frame["from"]
                if user_id in tables.local_users:
                    # Duplicate name error
                    await ws.send(protocol.make_envelope(
                        msg_type="ERROR", 
                        from_id=SERVER_ID, 
                        to_id=user_id,
                        payload= {
                            "code": "NAME_IN_USE", 
                            "detail": "User id already existed"}
                    ))
                else:
                    # Register on acceptance
                    tables.local_users[user_id] = ws
                    tables.user_locations[user_id] = "local"
                    print(f"[SERVER] Registered user {user_id}")


                    # acknowledge user hello request
                    await ws.send(protocol.make_envelope(
                        msg_type="ACK", 
                        from_id=SERVER_ID, 
                        to_id=user_id,
                        payload={"msg_ref": "USER_HELLO_OK"}
                    ))


                    # USER ADVERTISE
                    for target_server, server_ws in tables.servers.items():
                        await server_ws.send(protocol.make_envelope(
                            msg_type=ServerMessageType.USER_ADVERTISE,
                            from_id=SERVER_ID,
                            to_id=target_server,
                            payload={
                                "user_id": user_id,
                                "server_id": SERVER_ID,
                                "meta": {}   # TODO: attach username here
                            },
                            sig="..."  # TODO: sig
                        ))


                    # PUBLIC CHANNEL JOIN
                    # TODO: give user wrapped copy here
                    for target_server, server_ws in tables.servers.items():
                        await server_ws.send(protocol.make_envelope(
                            msg_type=ServerMessageType.PUBLIC_CHANNEL_ADD,
                            from_id=SERVER_ID,
                            to_id=target_server,
                            payload={
                                "add": [db.get_name(user_id)],
                                "if_version":  1
                            }
                        ))


                     # PUBLIC CHANNEL UPDATED 
                     # TODO: also reused this part when USER_REMOVE
                    for target_server, server_ws in tables.servers.items():
                        await server_ws.send(protocol.make_envelope(
                            msg_type=ServerMessageType.PUBLIC_CHANNEL_UPDATED,
                            from_id=SERVER_ID,
                            to_id=target_server,
                            payload={
                                "version": 2,  # TODO: configure version
                                "wraps":[
                                    {
                                        "member_id": "id",
                                        "wrapped_key": "..." # TODO: configure this
                                    },
                                    
                                ]
                            },
                            sig="..."
                        ))

                    

                    

                    

                    

                    
                
            # Handle direct message 
            elif msg_type == "MSG_DIRECT":
                sender = frame["from"]
                recipient = frame["to"]



                if recipient in tables.local_users:
                    # Deliver to local recipient
                    payload = frame["payload"]
                    new_payload = {
                        "ciphertext": payload["ciphertext"],
                        "sender": sender,
                        "sender_pub": payload["sender_pub"],
                        "content_sig": payload["content_sig"]
                    }

                    await tables.local_users[recipient].send(protocol.make_envelope(
                        msg_type="USER_DELIVER", 
                        from_id=SERVER_ID, 
                        to_id=recipient, 
                        payload=new_payload,
                        sig="<server_1 signature over payload>" # TODO: sig
                    ))
                    print(f"[SERVER] Delivered DM from {new_payload["sender"]} -> {recipient}")
                
                elif recipient in tables.user_locations and tables.user_locations != "local":
                    # Wrap as SERVER_DELIVER here
                    to_server_id = tables.user_locations[recipient]
                    server_ws = tables.servers[to_server_id]                    
                    payload = frame[payload]

                    # Wrap for server delivery
                    await server_ws.send(protocol.make_envelope(
                        msg_type=ServerMessageType.SERVER_DELIVER,
                        from_id=SERVER_ID,
                        to_id=to_server_id,
                        payload={
                            "user_id": recipient,
                            "ciphertext": payload["ciphertext"],
                            "sender": sender,
                            "sender_pub": payload["sender_pub"],
                            "content_sig": payload["content_sig"]
                        },
                        sig="<server_2 signature over payload>"
                    ))
                
                else:
                    # User not found
                    await ws.send(protocol.make_envelope(
                        msg_type="ERROR", 
                        from_id=SERVER_ID, 
                        to_id=sender,
                        payload= {
                            "code": "USER_NOT_FOUND", 
                            "detail": f"{recipient} not online"}
                    ))


                    print("[SERVER] user not found notification")

            elif msg_type == ServerMessageType.MSG_PUBLIC_CHANNEL:
                sender = frame["from"]
                group_id = frame["to"]  # this should always be public
                payload = frame["payload"]



                # fan to local members
                member_ids = db.get_member_ids_of_group(group_id) # TODO: Get member id from data table of public group
                for member_id in member_ids:
                    if member_id == sender:
                        continue
                        
                    if member_id in tables.local_users:
                        await tables.local_users[member_id].send(protocol.make_envelope(
                            msg_type=ServerMessageType.MSG_PUBLIC_CHANNEL, 
                            from_id=sender, 
                            to_id=group_id, 
                            payload=payload
                        ))


                # Only fan out to other servers if sender is local to avoid loop
                # NOTE: current data dont include identifier of users across server
                if sender in tables.local_users:
                    for to_server_id, server_ws in tables.servers.items():
                        if to_server_id != SERVER_ID:
                            await server_ws.send(frame)
          
                    



                        
            
            # Handle route file request
            elif msg_type in ["FILE_START", "FILE_CHUNK", "FILE_END"]:
                sender = frame["from"]
                recipient = frame["to"]

                if recipient in tables.local_users:
                    await tables.local_users[recipient].send(protocol.make_envelope(
                        msg_type=msg_type, 
                        from_id=sender, 
                        to_id=recipient, 
                        payload=frame["payload"]
                    ))
                    print(f"[SERVER] Delivered {msg_type} from {sender} -> {recipient}")
                
                elif recipient in tables.user_locations and tables.user_locations != "local":
                    # forward directly to other server
                    # NOTE: DO we need to wrap in SERVER_DELIVER???
                    await tables.user_locations[recipient].send(frame)

                else:
                    await ws.send(protocol.make_envelope(
                        msg_type="ERROR", 
                        from_id=SERVER_ID, 
                        to_id=sender,
                        payload= {
                            "code": "USER_NOT_FOUND", 
                            "detail": f"{recipient} not online"}
                    ))

            elif msg_type == CustomisedMessageType.LIST_REQUEST:
                sender = frame["from"]

                await ws.send(protocol.make_envelope(
                    msg_type=CustomisedMessageType.LIST_RESPONSE,
                    from_id=SERVER_ID,
                    to_id=sender,
                    payload={
                        "online_users": sorted(tables.user_locations.keys())
                    }
                ))
            else:
                print(f"[SERVER] Unhandled message: {frame}")

    except (websockets.exceptions.ConnectionClosedOK, 
            websockets.exceptions.ConnectionClosedError):
        print(f"[SERVER] Connection closed for {user_id}")

    finally:
        print(f"[SERVER] Connection closed for {user_id}")
        tables.local_users.pop(user_id)
        tables.user_locations.pop(user_id)

        # TODO: USER_REMOVE broadcast





async def start_server(host="localhost", port=8765):
    print(f"[SERVER] Starting on ws://{host}:{port}")
    async with websockets.serve(handle_client, host, port):
        await asyncio.Future()  # run forever


