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
            
            # group_id table SOCP 15.1
            # Public channel has group_id="public" and creator_id="system"
            conn.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    creator_id TEXT NOT NULL,
                    created_at INTEGER,
                    meta TEXT,
                    version INTEGER DEFAULT 1
                )
            """)
            
            # group_members SOCP 15.1
            conn.execute("""
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    role TEXT DEFAULT 'member',
                    wrapped_key TEXT NOT NULL,
                    added_at INTEGER,
                    PRIMARY KEY (group_id, member_id),
                    FOREIGN KEY (group_id) REFERENCES groups (group_id) ON DELETE CASCADE
                )
            """)
            
            # user sessions table (Chatgpt, "not in SOCP spec but useful for implementation")
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
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("""
                    INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (user_id, pubkey, privkey_store, pake_password, meta_json))
                
                wrapped_key = f"wrapped_key_for_{user_id}"  # TODO - RSA-OAEP encrypted channel key
                
                conn.execute("""
                    INSERT INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                    VALUES ('public', ?, 'member', ?, ?)
                """, (user_id, wrapped_key, int(datetime.now(timezone.utc).timestamp())))
                
                conn.commit()
                logger.info(f"User registered successfully: {user_id}")
                return user_id
                
        except sqlite3.IntegrityError as e:
            logger.error(f"Failed to register user {user_id}: {e}")
            raise ValueError(f"User ID {user_id} already exists")
    
    def authenticate_user(self, user_id: str, password: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT user_id, pake_password 
                FROM users 
                WHERE user_id = ?
            """, (user_id,)).fetchone()
            
            if not row:
                return None
            
            stored_user_id, stored_verifier = row
            
            # In production: perform PAKE verification here
            # For now, simplified check

            session_id = self.create_session(stored_user_id)
            print(f"Session ID: session_id")
            return stored_user_id
    
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
                conn.execute("""
                    INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                    VALUES (?, ?, ?, ?, 1)
                """, (group_id, creator_id, created_at, meta_json))
                
                wrapped_key = f"wrapped_key_for_{creator_id}"  # Placeholder
                
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