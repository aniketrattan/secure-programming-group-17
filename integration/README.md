# Secure Overlay Chat Protocol (SOCP) – Integration Guide

This folder contains a reference implementation of the SOCP server and client with end-to-end encrypted DMs, a persisted public channel, file transfer, presence gossip, and server-to-server routing over WebSockets.

## Installation

Install Python dependencies:

```cmd
python -m pip install -r integration\requirements.txt
```

## Running servers (multi-node mesh)

SOCP requires a UUID v4 for each server. Use different ports for each server.

1) Generate two UUIDs:
```cmd
python -c "import uuid; print(uuid.uuid4()); print(uuid.uuid4())"
```

2) Start server A on 8765:
```cmd
python -m integration.run_server --bind ws://127.0.0.1:8765 --server-id <UUID_A>
```

3) Start server B on 8766 and peer to A:
```cmd
python -m integration.run_server --bind ws://127.0.0.1:8766 --server-id <UUID_B> --peer ws://127.0.0.1:8765
```

Expected logs:
- Server B: “Connected to peer ws://127.0.0.1:8765”.
- Server A: “Server joining …”, then “Server announced: <UUID_B>”.
- Periodic status shows both in “Known servers”.

Notes:
- Use different ports for each server; peering to the same port you’re bound on won’t work.

## Running clients

Start one client per server to test cross-server routing.

Client 1 (to A):
```cmd
python -m integration.run_client --server ws://127.0.0.1:8765
```

Client 2 (to B):
```cmd
python -m integration.run_client --server ws://127.0.0.1:8766
```

## Client commands (features)

All commands are typed in the client terminal.

### 1) Register (generates keys, stores a protected private key)
```
/register
```
You’ll be shown your new user UUID and prompted to set a password (used to protect your private key at rest).

### 2) Login
```
/login <user_uuid>
```
On success, you’ll see `[LOGIN SUCCESS]`. The client recovers your private key and sends `USER_HELLO` to attach presence.

### 3) List online users
```
/list
```
Returns a sorted list of online user UUIDs (across servers, via gossip).

### 4) Direct message (DM, end-to-end encrypted)
```
/tell <recipient_uuid> <message>
```
Behavior:
- Client encrypts with recipient’s RSA-4096 pubkey and signs content.
- Server verifies DM `content_sig` and drops malformed messages early.
- Recipient sees: `DM from <sender_uuid>: <text>`.

### 5) Public channel (broadcast)
```
/all <text>
```
Behavior:
- Per-member RSA encryption and content signatures.
- Server does not decrypt; fans out to each member’s hosting server.
- Public channel version is persisted and bumps on join/leave.

### 6) File transfer
```
/file <recipient_uuid> <path_to_file>
```
Behavior:
- Sends FILE_START → FILE_CHUNK(s) → FILE_END.
- Each chunk is RSA-OAEP encrypted and signed; server/client verify timestamps and signatures.
- Recipient writes `received_<file_id>` when complete.


## Quick test recipe

1) Start two servers (UUID v4 IDs) on 8765 and 8766, peering B→A.
2) Start one client per server; `/register` then `/login` on both.
3) Run `/list` on either client – both UUIDs should appear.
4) Send `/tell <other_uuid> hello` and `/all hello-public`.
5) Try `/file <other_uuid> <a_small_file>` and check recipient output.
