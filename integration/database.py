import sqlite3
import hashlib
import secrets
import json
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging
import uuid
from .crypto_services.rsa import load_public_key_b64url


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserStatus(Enum):
    OFFLINE = "offline"
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"

# CHANGED: Simplified to match SOCP spec - only PUBLIC channels required
class ChannelType(Enum):
    PUBLIC = "public"
    PRIVATE = "private"  # Optional extension
    DIRECT_MESSAGE = "dm"  # Optional extension

# CHANGED: Added role enum to match SOCP spec
class MemberRole(Enum):
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"

@dataclass
class User:
    user_id: str
    username: str
    display_name: Optional[str] = None
    avatar_hash: Optional[str] = None
    status: UserStatus = UserStatus.OFFLINE
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    version: int = 1

@dataclass
class Channel:
    channel_id: str
    name: str
    channel_type: ChannelType
    creator_id: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    version: int = 1

class SecureMessagingDB:
    def __init__(self, db_path: str = "secure_messaging.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            
            # users table SOCP 15.1, heartbeat optional from SOCP 8.4
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    privkey_store TEXT NOT NULL,
                    pake_password TEXT NOT NULL,
                    meta TEXT,
                    version INTEGER NOT NULL,
                    status TEXT DEFAULT 'offline',
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Ensure required columns exist if the table pre-dates this schema
            self._migrate_users_table(conn)
            
            # group_id table SOCP 15.1
            # Public channel has group_id="public" and creator_id="system"
            conn.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    creator_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    meta TEXT,
                    version INTEGER NOT NULL DEFAULT 1
                )
            """)
            
            # group_members SOCP 15.1
            conn.execute("""
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    role TEXT DEFAULT 'member',
                    wrapped_key TEXT NOT NULL,
                    added_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, member_id),
                    FOREIGN KEY (group_id) REFERENCES groups (group_id) ON DELETE CASCADE
                )
            """)
            
            # user sessions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                )
            """)

            # Minimal public-channel membership table (kept for compatibility; not the source of truth)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS channel_members (
                    channel_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    PRIMARY KEY (channel_id, user_id)
                )
            """)

            # Trusted server key pins (persisted trust)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_servers (
                    server_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    ws_uri TEXT,
                    added_at INTEGER NOT NULL
                )
            """)
            
            # Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_groups_creator ON groups (creator_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_group_members_member ON group_members (member_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions (user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions (is_active)")
            
            # ADDED: Initialize public channel per SOCP spec
            self._initialize_public_channel(conn)
            
            conn.commit()
            logger.info("Database initialized successfully (SOCP v1.3 compliant)")
        # Ensure existence after closing prior write transaction to avoid locks
        self.ensure_public_channel_exists()

    def _migrate_users_table(self, conn):
        cols = {row[1] for row in conn.execute("PRAGMA table_info('users')").fetchall()}
        altered = False
        if 'privkey_store' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN privkey_store TEXT NOT NULL DEFAULT ''")
            altered = True
        if 'pake_password' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN pake_password TEXT NOT NULL DEFAULT ''")
            altered = True
        if 'version' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
            altered = True
        if altered:
            conn.execute("UPDATE users SET updated_at=CURRENT_TIMESTAMP")
    
    def _initialize_public_channel(self, conn):
        """ADDED: Initialize the required public channel per SOCP spec."""
        # Check if public channel already exists
        row = conn.execute("SELECT group_id FROM groups WHERE group_id = 'public'").fetchone()
        if not row:
            # Create public channel with creator_id="system"
            conn.execute("""
                INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                VALUES ('public', 'system', ?, '{"title": "Public Channel"}', 1)
            """, (int(datetime.now(timezone.utc).timestamp()),))
            logger.info("Public channel initialized")

    # ---- Public channel minimal membership helpers ----
    def ensure_public_channel_exists(self) -> str:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT group_id FROM groups WHERE group_id='public'").fetchone()
            if not row:
                conn.execute("""
                    INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                    VALUES ('public', 'system', ?, '{"title":"Public Channel"}', 1)
                """, (int(datetime.now(timezone.utc).timestamp()),))
                conn.commit()
        return "public"

    def add_member_to_public(self, user_id: str) -> None:
        """Add membership to 'public' in group_members and mirror to channel_members.
        The group_members table is the source of truth; channel_members is mirrored for legacy callers.
        """
        with sqlite3.connect(self.db_path) as conn:
            # Ensure 'public' group exists
            conn.execute(
                """
                INSERT OR IGNORE INTO groups (group_id, creator_id, created_at, meta, version)
                VALUES ('public','system', ?, '{"title":"Public Channel"}', 1)
                """,
                (int(datetime.now(timezone.utc).timestamp()),),
            )
            # Insert group membership with a placeholder wrapped_key
            wrapped_key = f"wrapped_key_for_{user_id}"
            conn.execute(
                """
                INSERT OR IGNORE INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                VALUES ('public', ?, 'member', ?, ?)
                """,
                (user_id, wrapped_key, int(datetime.now(timezone.utc).timestamp())),
            )
            # Mirror to channel_members (compat)
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO channel_members (channel_id, user_id) VALUES ('public', ?)",
                    (user_id,),
                )
            except sqlite3.Error:
                pass
            conn.commit()

    def set_wrapped_public_key(self, member_id: str, wrapped_b64: str, added_at: int) -> None:
        with sqlite3.connect(self.db_path) as conn:
            # Ensure group and member rows exist
            conn.execute(
                "INSERT OR IGNORE INTO groups (group_id, creator_id, created_at, meta, version) VALUES ('public','system', ?, '{\"title\":\"Public Channel\"}', 1)",
                (int(datetime.now(timezone.utc).timestamp()),)
            )
            conn.execute(
                "INSERT OR REPLACE INTO group_members (group_id, member_id, role, wrapped_key, added_at) VALUES ('public', ?, COALESCE((SELECT role FROM group_members WHERE group_id='public' AND member_id=?),'member'), ?, ?)",
                (member_id, member_id, wrapped_b64, added_at)
            )
            conn.commit()

    def remove_member_from_public(self, user_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            # Remove from source-of-truth table
            conn.execute(
                "DELETE FROM group_members WHERE group_id='public' AND member_id=?",
                (user_id,),
            )
            # Mirror delete to channel_members (compat)
            try:
                conn.execute(
                    "DELETE FROM channel_members WHERE channel_id='public' AND user_id=?",
                    (user_id,),
                )
            except sqlite3.Error:
                pass
            conn.commit()

    def get_public_members(self) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT member_id FROM group_members WHERE group_id='public'"
            ).fetchall()
            return [r[0] for r in rows]

    def get_public_version(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT version FROM groups WHERE group_id='public'"
            ).fetchone()
            return int(row[0]) if row and row[0] is not None else 1

    # ---- Trusted server key pins ----
    def upsert_trusted_server(self, server_id: str, pubkey: str, ws_uri: Optional[str] = None) -> None:
        # Enforce UUID v4 server_id
        try:
            if str(uuid.UUID(server_id, version=4)) != server_id:
                raise ValueError
        except Exception as exc:
            raise ValueError("Invalid UUID v4 server_id") from exc
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO trusted_servers (server_id, pubkey, ws_uri, added_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(server_id) DO UPDATE SET
                    pubkey=excluded.pubkey,
                    ws_uri=COALESCE(excluded.ws_uri, trusted_servers.ws_uri)
                """,
                (server_id, pubkey, ws_uri, int(datetime.now(timezone.utc).timestamp())),
            )
            conn.commit()

    def get_trusted_server_pubkey(self, server_id: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT pubkey FROM trusted_servers WHERE server_id=?",
                (server_id,),
            ).fetchone()
            return row[0] if row else None

    def load_trusted_mapping(self) -> Dict[str, str]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT server_id, pubkey FROM trusted_servers").fetchall()
            return {r[0]: r[1] for r in rows}

    def get_display_name(self, user_id: str) -> str:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT meta FROM users WHERE user_id=?", (user_id,)).fetchone()
            if row and row[0]:
                try:
                    meta = json.loads(row[0])
                    name = meta.get('display_name')
                    if name:
                        return name
                except Exception:
                    pass
            return user_id
    
    def generate_user_id(self) -> str:
        return str(uuid.uuid4())
    
    def generate_group_id(self) -> str:
        return str(uuid.uuid4())
    
    def hash_password_pake(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode(), 
                                          salt.encode(), 
                                          100000).hex()
        return password_hash, salt
    
    def register_user(self, user_id: str, pubkey: str, privkey_store: str,
                     pake_password: str, meta: Optional[Dict] = None) -> str:
        meta_json = json.dumps(meta) if meta else None
        # Enforce UUID v4 user_id
        try:
            if str(uuid.UUID(user_id, version=4)) != user_id:
                raise ValueError
        except Exception as exc:
            raise ValueError("Invalid UUID v4 user_id") from exc
        # Enforce RSA-4096 public key
        try:
            public_key = load_public_key_b64url(pubkey)
        except Exception as exc:
            raise ValueError("Invalid RSA-4096 public key") from exc

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")
                # Insert or update with version bump on replace
                conn.execute(
                    """
                    INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(user_id) DO UPDATE SET
                        pubkey=excluded.pubkey,
                        privkey_store=excluded.privkey_store,
                        pake_password=excluded.pake_password,
                        meta=excluded.meta,
                        version=users.version + 1,
                        updated_at=CURRENT_TIMESTAMP
                    """,
                    (user_id, pubkey, privkey_store, pake_password, meta_json),
                )

                # UPDATED: Generate and wrap public channel key for this user
                if self.crypto:
                    # Get or create public channel group key
                    group_key = self._get_or_create_public_channel_key(conn)

                    # Wrap the group key for this user
                    wrapped_key = self.wrap_group_key(group_key, pubkey)
                else:
                    # Fallback if crypto not available (for testing)
                    wrapped_key = f"wrapped_key_for_{user_id}"
                    logger.warning("Crypto module not available, using placeholder wrapped key")

                conn.execute(
                    """
                    INSERT OR IGNORE INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                    VALUES ('public', ?, 'member', ?, ?)
                    """,
                    (user_id, wrapped_key, int(datetime.now(timezone.utc).timestamp())),
                )

                conn.commit()
                logger.info(f"User registered successfully: {user_id}")
                return user_id
                
        except sqlite3.IntegrityError as e:
            logger.error(f"Failed to register user {user_id}: {e}")
            raise ValueError(f"User ID {user_id} already exists")

     def _get_or_create_public_channel_key(self, conn) -> bytes:
            """
            ADDED: Get or create the public channel's group key.

            In a real implementation, this would be stored securely or derived.
            For simplicity, we'll store it in the groups.meta field.

            Args:
                conn: Active SQLite connection

            Returns:
                32-byte group key
            """
            # Try to get existing key from meta
            row = conn.execute("""
                SELECT meta FROM groups WHERE group_id = 'public'
            """).fetchone()

            if row and row[0]:
                meta = json.loads(row[0])
                if 'group_key_hex' in meta:
                    return bytes.fromhex(meta['group_key_hex'])

            # Generate new group key
            group_key = self.generate_group_key()

            # Store it in meta (in production, use proper key management)
            meta = json.loads(row[0]) if row and row[0] else {}
            meta['group_key_hex'] = group_key.hex()

            conn.execute("""
                UPDATE groups SET meta = ? WHERE group_id = 'public'
            """, (json.dumps(meta),))

            logger.info("Generated new public channel group key")
            return group_key

    def generate_group_key(self) -> bytes:
            """
            ADDED: Generate a random 256-bit group key.
            This is the key that will be wrapped for each member.
            """
            return secrets.token_bytes(32)  # 256 bits

        def wrap_group_key(self, group_key: bytes, recipient_pubkey_b64: str) -> str:
            """
            ADDED: Wrap a group key using the recipient's RSA-4096 public key.

            Args:
                group_key: 32-byte group key to wrap
                recipient_pubkey_b64: base64url encoded RSA-4096 public key

            Returns:
                base64url encoded wrapped key (no padding)
            """
            if not self.crypto:
                raise RuntimeError("Crypto module not initialized")

            # Load the public key from base64url
            pub_key = self.crypto.load_public_key_b64url(recipient_pubkey_b64)

            # Encrypt the group key using RSA-OAEP
            wrapped_bytes = self.crypto.encrypt_rsa_oaep(group_key, pub_key)

            # Encode to base64url
            return self.crypto.b64url_encode(wrapped_bytes)


    def get_user_auth(self, user_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT pubkey, privkey_store, pake_password, version
                FROM users
                WHERE user_id=?
                """,
                (user_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "pubkey": row[0],
                "privkey_store": row[1],
                "pake_password": row[2],
                "version": row[3],
            }
    
    def get_pubkey(self, user_id: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT pubkey FROM users WHERE user_id = ?
            """, (user_id,)).fetchone()
            
            return row[0] if row else None
    
    def get_user_keys(self, user_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT pubkey, privkey_store, version
                FROM users 
                WHERE user_id = ?
            """, (user_id,)).fetchone()
            
            if row:
                return {
                    'pubkey': row[0],
                    'privkey_store': row[1],
                    'version': row[2]
                }
            return None
    
    def update_presence(self, user_id: str, status: str, 
                       session_id: Optional[str] = None) -> bool:
        """Update user's presence status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Update user status
                conn.execute("""
                    UPDATE users 
                    SET status = ?, last_seen = CURRENT_TIMESTAMP, 
                        updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                """, (status, user_id))
                
                # Update session activity if session_id provided
                if session_id:
                    conn.execute("""
                        UPDATE user_sessions 
                        SET last_activity = CURRENT_TIMESTAMP
                        WHERE session_id = ? AND user_id = ?
                    """, (session_id, user_id))
                
                conn.commit()
                return conn.total_changes > 0
        except sqlite3.Error as e:
            logger.error(f"Failed to update presence for {user_id}: {e}")
            return False
    
    def get_user_info(self, user_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT user_id, meta, status, last_seen, created_at, version
                FROM users 
                WHERE user_id = ?
            """, (user_id,)).fetchone()
            
            if row:
                meta = json.loads(row[1]) if row[1] else {}
                return {
                    'user_id': row[0],
                    'meta': meta,
                    'display_name': meta.get('display_name', row[0]),  # ADDED: Fallback per SOCP 15.2
                    'status': row[2],
                    'last_seen': row[3],
                    'created_at': row[4],
                    'version': row[5]
                }
            return None
    
    def create_group(self, group_id: str, creator_id: str, meta: Optional[Dict] = None) -> str:
        meta_json = json.dumps(meta) if meta else None
        created_at = int(datetime.now(timezone.utc).timestamp())
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")

                group_key = self.generate_group_key()

                # Store group key in meta (for future member additions)
                meta_dict = meta.copy() if meta else {}
                meta_dict['group_key_hex'] = group_key.hex()
                meta_json = json.dumps(meta_dict)

                conn.execute("""
                    INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                    VALUES (?, ?, ?, ?, 1)
                """, (group_id, creator_id, created_at, meta_json))
                
                if self.crypto:
                    # Get creator's public key
                    creator_pubkey = self.get_pubkey(creator_id)
                    if not creator_pubkey:
                        raise ValueError(f"Public key not found for creator {creator_id}")

                    # Wrap the group key for the creator
                    wrapped_key = self.wrap_group_key(group_key, creator_pubkey)
                    logger.info(f"Generated wrapped key for creator {creator_id}")
                else:
                    # Fallback if crypto not available (for testing)
                    wrapped_key = f"wrapped_key_for_{creator_id}"
                    logger.warning("Crypto module not available, using placeholder wrapped key")

                conn.execute("""
                    INSERT INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                    VALUES (?, ?, 'owner', ?, ?)
                """, (group_id, creator_id, wrapped_key, created_at))


                conn.commit()
                logger.info(f"Group created: {group_id}")
                return group_id
                
        except sqlite3.Error as e:
            logger.error(f"Failed to create group {group_id}: {e}")
            raise
     
    def get_wrapped_key(self, group_id: str, member_id: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT wrapped_key FROM group_members
                WHERE group_id = ? AND member_id = ?
            """, (group_id, member_id)).fetchone()
            
            return row[0] if row else None
    
    def join_group(self, group_id: str, member_id: str, wrapped_key: str, role: str = "member") -> bool:
        added_at = int(datetime.now(timezone.utc).timestamp())

        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if user is already a member of this group
                existing = conn.execute("""
                    SELECT member_id FROM group_members 
                    WHERE group_id = ? AND member_id = ?
                """, (group_id, member_id)).fetchone()
                
                if existing:
                    logger.warning(f"User {member_id} is already a member of group {group_id}")
                    return False

                conn.execute("""
                    INSERT OR REPLACE INTO group_members 
                    (group_id, member_id, role, wrapped_key, added_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (group_id, member_id, role, wrapped_key, added_at))
                
                conn.commit()
                self.update_user_version(member_id)
                logger.info(f"User {member_id} joined group {group_id}")
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Failed to join group {group_id}: {e}")
            return False
    
    def get_user_groups(self, user_id: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT g.group_id, g.meta, gm.role, gm.added_at, g.version
                FROM groups g
                JOIN group_members gm ON g.group_id = gm.group_id
                WHERE gm.member_id = ?
                ORDER BY gm.added_at DESC
            """, (user_id,)).fetchall()
            
            result = []
            for row in rows:
                meta = json.loads(row[1]) if row[1] else {}
                result.append({
                    'group_id': row[0],
                    'title': meta.get('title', row[0]),  # ADDED: Fallback per SOCP 15.2
                    'meta': meta,
                    'role': row[2],
                    'added_at': row[3],
                    'version': row[4]
                })
            return result
    
    def get_group_members(self, group_id: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT u.user_id, u.meta, u.status, gm.role, gm.wrapped_key, gm.added_at
                FROM users u
                JOIN group_members gm ON u.user_id = gm.member_id
                WHERE gm.group_id = ?
                ORDER BY gm.added_at
            """, (group_id,)).fetchall()
            
            result = []
            for row in rows:
                meta = json.loads(row[1]) if row[1] else {}
                result.append({
                    'user_id': row[0],
                    'display_name': meta.get('display_name', row[0]),  # ADDED: Fallback
                    'meta': meta,
                    'status': row[2],
                    'role': row[3],
                    'wrapped_key': row[4],
                    'added_at': row[5]
                })
            return result
    
    def update_user_version(self, user_id: str) -> int:
        """Increment user version (for key rotation/metadata updates)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE users 
                SET version = version + 1, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (user_id,))
            
            # Get new version
            row = conn.execute("""
                SELECT version FROM users WHERE user_id = ?
            """, (user_id,)).fetchone()
            
            conn.commit()
            return row[0] if row else 0

    def set_user_version(self, user_id: str, version: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE users SET version=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?
                """,
                (version, user_id),
            )
            row = conn.execute("SELECT version FROM users WHERE user_id=?", (user_id,)).fetchone()
            conn.commit()
            return row[0] if row else 0

    def bump_user_version(self, user_id: str) -> int:
        return self.update_user_version(user_id)
    
    def update_group_version(self, group_id: str) -> int:
        """Increment group version (for member changes/key rotation)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE groups 
                SET version = version + 1
                WHERE group_id = ?
            """, (group_id,))
            
            row = conn.execute("""
                SELECT version FROM groups WHERE group_id = ?
            """, (group_id,)).fetchone()
            
            conn.commit()
            return row[0] if row else 0
    
    def create_session(self, user_id: str, device_id: Optional[str] = None,
            ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> str:
        
        session_id = secrets.token_urlsafe(32)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO user_sessions 
                (session_id, user_id, device_id, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, user_id, device_id, ip_address, user_agent))
            conn.commit()
        
        return session_id
    
    def cleanup_sessions(self, max_age_hours: int = 24):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE user_sessions 
                SET is_active = 0
                WHERE datetime(last_activity) < datetime('now', '-{} hours')
            """.format(max_age_hours))
            conn.commit()
    
    def get_online_users(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT user_id, meta, status, last_seen
                FROM users 
                WHERE status != 'offline'
                ORDER BY last_seen DESC
            """).fetchall()
            
            result = []
            for row in rows:
                meta = json.loads(row[1]) if row[1] else {}
                result.append({
                    'user_id': row[0],
                    'display_name': meta.get('display_name', row[0]),  # ADDED: Fallback
                    'meta': meta,
                    'status': row[2],
                    'last_seen': row[3]
                })
            return result


