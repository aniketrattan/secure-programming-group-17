# 🔐 Secure Overlay Chat Protocol (SOCP) – Implementation

> **A decentralized, end-to-end encrypted messaging system with server-to-server routing over WebSockets**

---

## 🚀 Quick Start

### Installation

Install Python dependencies:

```bash
pip install -r requirements.txt
```

### 🏗️ Server Setup (Introducer Architecture)

SOCP uses an **introducer-based bootstrap** system where the first server acts as an introducer and assigns UUIDs to subsequent servers.

#### 1️⃣ Start the Introducer Server
```bash
python run_server.py --bind ws://127.0.0.1:8765 --server-id auto
```
> The first server with `--server-id auto` becomes the introducer and gets assigned a UUID automatically.

#### 2️⃣ Start Additional Servers
```bash
python run_server.py --bind ws://127.0.0.1:8766 --server-id auto --peer ws://127.0.0.1:8765
python run_server.py --bind ws://127.0.0.1:8767 --server-id auto --peer ws://127.0.0.1:8765
```

**Expected Behavior:**
- ✅ Introducer assigns UUIDs to new servers automatically
- ✅ Servers announce themselves to the mesh network
- ✅ Cross-server routing establishes automatically
- ✅ Periodic status shows all servers in "Known servers"

> **💡 Note:** Use different ports for each server.

**Address Error**
The error can be returned due to different OS. If you encountered error when starting servers, please try the below commands.


```bash
# Introducer server
python run_server.py --bind ws://127.0.0.1:8765 --server-id auto --http 127.0.0.1:8080
```

```bash
# Additional servers
python run_server.py --bind ws://127.0.0.1:8766 --server-id auto --peer ws://127.0.0.1:8765 --http 127.0.0.1:8081

python run_server.py --bind ws://127.0.0.1:8767 --server-id auto --peer ws://127.0.0.1:8765 --http 127.0.0.1:8082
```



### 👥 Client Setup

Start clients connected to different servers to test cross-server messaging:

**Client 1 (connected to Server A):**
```bash
python run_client.py --server ws://127.0.0.1:8765
```

**Client 2 (connected to Server B):**
```bash
python run_client.py --server ws://127.0.0.1:8766
```

---

## 💬 Client Commands & Features

All commands are typed directly in the client terminal.

### 🔐 Authentication

#### `/register`
Creates a new user account with RSA-4096 keypair generation.
- Generates and stores a protected private key
- Prompts for password (protects private key at rest)
- Returns your new user UUID
- After registration, you need to claim a username for easier identification

#### `/login <username_or_uuid>`
Authenticates with your existing account using either:
- **Username**: `alice`, `bob`, `charlie` (case-insensitive)
- **UUID**: Full UUID v4 format
- Recovers your private key using your password
- Sends `USER_HELLO` to attach presence
- Shows `[LOGIN SUCCESS]` on successful authentication

### 👥 User Management

#### `/list`
Lists all online users across the entire server mesh.
- Returns sorted list of usernames
- Updates via presence gossip from all servers
- Shows users from any connected server
- **Example**: `Online users: alice, bob, charlie`

### 💌 Messaging

#### `/tell <recipient> <message>`
Sends an **end-to-end encrypted** direct message.
- **Recipient**: Can be username (`alice`) or UUID
- Encrypts with recipient's RSA-4096 public key
- Signs content with your private key
- Server verifies signature and drops malformed messages
- Recipient sees: `DM from <sender_username>: <message>`

#### `/all <message>`
Broadcasts to the **public channel** (all users).
- Per-member RSA encryption with content signatures
- Server never decrypts; forwards to each member's hosting server
- Public channel version persists and increments on join/leave
- Message reaches all users across the entire mesh

### 📁 File Transfer

#### `/file <recipient> <path_to_file>`
Transfers files securely with chunked encryption.
- **Recipient**: Can be username (`alice`) or UUID
- Sends `FILE_START` → `FILE_CHUNK(s)` → `FILE_END`
- Each chunk is RSA-OAEP encrypted and signed
- Server/client verify timestamps and signatures
- Recipient saves as `received_<file_id>` when complete

---

## 🧪 Testing Guide

### Complete Test Workflow

1. **🏗️ Start Server Mesh**
   ```bash
   # Terminal 1: Start introducer
   python run_server.py --bind ws://127.0.0.1:8765 --server-id auto
   
   # Terminal 2: Start additional server
   python run_server.py --bind ws://127.0.0.1:8766 --server-id auto --peer ws://127.0.0.1:8765
   ```

2. **👥 Start Clients**
   ```bash
   # Terminal 3: Client 1
   python run_client.py --server ws://127.0.0.1:8765
   
   # Terminal 4: Client 2  
   python run_client.py --server ws://127.0.0.1:8766
   ```

3. **🔐 Register & Login**
   ```bash
   # In Client 1 terminal:
   /register
   /login <your_uuid_or_username_from_register>
   
   # In Client 2 terminal:
   /register
   /login <your_uuid_or_username_from_register>
   ```

4. **✅ Verify Cross-Server Communication**
   ```bash
   # Check both users are visible (shows usernames)
   /list
   
   # Send encrypted DM using usernames
   /tell alice Hello from across servers!
   
   # Send public message
   /all Testing public channel across mesh!
   
   # Test file transfer using usernames
   /file alice test.txt
   ```

### 🎯 Expected Results
- ✅ Both usernames appear in `/list` from either client
- ✅ Direct messages delivered with `DM from <username>: <message>` format
- ✅ Public messages broadcast to all users
- ✅ File transfers complete with `received_<file_id>` files

---
