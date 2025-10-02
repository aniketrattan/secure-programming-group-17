# In-memory tables (spec §5.2)

servers = {}        # server_id -> WebSocket
server_addrs = {}   # server_id -> (host, port)
local_users = {}    # user_id -> WebSocket
user_locations = {} # user_id -> "local" | "server_<id>"
