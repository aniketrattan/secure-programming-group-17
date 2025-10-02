#!/usr/bin/env python3
"""
Standalone terminal client for development & testing WITHOUT any server or other users.

Features:
 - /list, /tell, /all, /file, /help, /history, /simulate, /quit
 - Local echo of sent messages
 - Simulated incoming frames via /simulate
 - Colors, timestamps, scrollback (history), logging
 - Simulated simple verify/decrypt helpers (NOT real crypto)
"""

import asyncio
import base64
import json
import os
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from textwrap import shorten

try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    print("Missing dependency: colorama. Install with `pip install colorama`")
    sys.exit(1)

colorama_init(autoreset=True)

# -------------------------
# Config
# -------------------------
SCROLLBACK = 500
LOGFILE = "chat_client.log"
SENT_DIR = Path("sent")
SENT_DIR.mkdir(exist_ok=True)
USER_ID = os.environ.get("CHAT_USER", "localuser")

scrollback = deque(maxlen=SCROLLBACK)

### Logging
def log_line(line: str):
    ts = datetime.now(timezone.utc).astimezone().isoformat()
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(f"{ts} {line}\n")

#########################  helpers
def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()

def pretty_ts(iso_ts):
    try:
        dt = datetime.fromisoformat(iso_ts)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_ts

def colored(kind: str, text: str) -> str:
    if kind == "error":
        return Fore.RED + text + Style.RESET_ALL
    if kind == "dm":
        return Fore.CYAN + text + Style.RESET_ALL
    if kind == "all":
        return Fore.GREEN + text + Style.RESET_ALL
    if kind == "system":
        return Fore.YELLOW + text + Style.RESET_ALL
    return text

def display_and_log(text: str):
    print(text)
    scrollback.append(text)
    log_line(text)

# -------------------------
# Toy crypto helpers (simulate)
# -------------------------
def sign_payload_sim(payload: bytes) -> str:
    """Return a toy 'signature' (base64) -- deterministic for testing."""
    sig = b"SIG:" + payload[:16]
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")

def verify_signature_sim(payload: bytes, signature_b64: str, signer_id: str) -> bool:
    """Toy verify: if payload contains '--invalidsig' treat as invalid; else valid."""
    try:
        decoded = base64.urlsafe_b64decode(signature_b64 + "==")
    except Exception:
        return False
    # For testing: if payload contains the literal bytes b'--invalidsig', fail verify.
    if b"--invalidsig" in payload:
        return False
    # Basic structural check
    return decoded.startswith(b"SIG:")

def encrypt_sim(plaintext: bytes, recipient: str) -> str:
    """Toy 'encrypt' as urlsafe-base64 (not real encryption)."""
    return base64.urlsafe_b64encode(plaintext).decode().rstrip("=")

def decrypt_sim(ciphertext_b64: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(ciphertext_b64 + "==")
    except Exception:
        return b"<decrypt-failed>"

# -------------------------
# Frame handling (local-only)
# -------------------------
def build_frame(frame_type: str, frm: str, to: str | None, payload: dict) -> dict:
    ts = now_iso()
    frame = {"type": frame_type, "from": frm, "to": to, "ts": ts, "payload": payload}
    # toy signature based on canonical rule - different for DM vs ALL
    if frame_type == "DM":
        sign_input = (payload.get("ciphertext", "") + (to or "") + ts).encode("utf-8")
    else:
        sign_input = (payload.get("ciphertext", "") + ts).encode("utf-8")
    frame["sig"] = sign_payload_sim(sign_input)
    return frame

def display_incoming(frame: dict):
    t = frame.get("type", "UNKNOWN")
    frm = frame.get("from", "<unknown>")
    ts = pretty_ts(frame.get("ts", now_iso()))
    payload = frame.get("payload", {})

    if t == "DM":
        ciphertext = payload.get("ciphertext", "")
        sign_input = (ciphertext + frm + (frame.get("to") or "") + frame.get("ts", "")).encode("utf-8")
        ok = verify_signature_sim(sign_input, frame.get("sig", ""), frm)
        if not ok:
            display_and_log(colored("error", f"[{ts}] INVALID SIG on DM from {frm}"))
            return
        pt = decrypt_sim(ciphertext).decode("utf-8", errors="replace")
        out = colored("dm", f"[{ts}] (DM) {frm}: {pt}")
        display_and_log(out)
    elif t in ("BROADCAST", "ALL"):
        ciphertext = payload.get("ciphertext", "")
        sign_input = (ciphertext + frame.get("ts", "")).encode("utf-8")
        ok = verify_signature_sim(sign_input, frame.get("sig", ""), frm)
        if not ok:
            display_and_log(colored("error", f"[{ts}] INVALID SIG on broadcast from {frm}"))
            return
        pt = decrypt_sim(ciphertext).decode("utf-8", errors="replace")
        out = colored("all", f"[{ts}] (ALL) {frm}: {pt}")
        display_and_log(out)
    elif t == "ERROR":
        msg = payload.get("message", "<no message>")
        display_and_log(colored("error", f"[{ts}] (ERROR) {msg}"))
    elif t == "USER_LIST":
        users = payload.get("users", [])
        display_and_log(colored("system", f"[{ts}] Online users: {', '.join(users)}"))
    elif t.startswith("FILE_"):
        # minimal file handling messages
        if t == "FILE_OFFER":
            offer_id = payload.get("offer_id")
            filename = payload.get("filename", "unnamed")
            size = payload.get("size", 0)
            display_and_log(colored("system", f"[{ts}] File offer from {frm}: {filename} ({size} bytes) offer_id={offer_id}"))
        elif t == "FILE_CHUNK":
            display_and_log(colored("system", f"[{ts}] Received file chunk from {frm} (len={len(payload.get('chunk',''))})"))
        elif t == "FILE_END":
            display_and_log(colored("system", f"[{ts}] File transfer finished from {frm}"))
        else:
            display_and_log(colored("system", f"[{ts}] FILE frame {t} from {frm}"))
    else:
        display_and_log(colored("system", f"[{ts}] {t} from {frm}: {shorten(json.dumps(payload), width=200)}"))

####################################################### Commands
def cmd_help():
    help_text = """
Available commands:
  /help                         Show this help
  /list                         Show (local) online users
  /tell <user> <text>           Send a DM (local echo)
  /all <text>                   Broadcast to all (local echo)
  /file <user> <path>           "Send" file (reads and writes a sent copy to sent/)
  /history                      Show recent message history
  /simulate <type> [args...]    Simulate incoming frames:
                                - dm <from> <text>
                                - all <from> <text>
                                - error <message>
                                - file_offer <from> <filename> <size>
  /quit                         Quit
Notes:
  - You can type plain text (no leading /) and it will be treated as /all <text>.
  - To simulate an invalid signature, include the literal substring --invalidsig in the simulated text.
"""
    print(help_text)

def cmd_list():
    # Local-only fake list
    users = [USER_ID, "alice", "bob", "carol"]
    display_and_log(colored("system", f"[{pretty_ts(now_iso())}] Online users: {', '.join(users)}"))

def cmd_tell(to: str, text: str):
    ciphertext = encrypt_sim(text.encode("utf-8"), to)
    payload = {"ciphertext": ciphertext}
    frame = build_frame("DM", USER_ID, to, payload)
    # local echo as SENT
    display_and_log(colored("dm", f"[{pretty_ts(frame['ts'])}] (DM SENT) to {to}: {text}"))
    log_line(f"SENT_FRAME {json.dumps(frame)}")

def cmd_all(text: str):
    ciphertext = encrypt_sim(text.encode("utf-8"), "group")
    payload = {"ciphertext": ciphertext}
    frame = build_frame("BROADCAST", USER_ID, None, payload)
    display_and_log(colored("all", f"[{pretty_ts(frame['ts'])}] (ALL SENT) {USER_ID}: {text}"))
    log_line(f"SENT_FRAME {json.dumps(frame)}")

def cmd_file(to: str, path: str):
    p = Path(path)
    if not p.exists() or not p.is_file():
        display_and_log(colored("error", f"File not found: {path}"))
        return
    offer_id = base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=")
    size = p.stat().st_size
    filename = p.name
    # Send offer (local echo + write a "sent" copy)
    frame_offer = build_frame("FILE_OFFER", USER_ID, to, {"offer_id": offer_id, "filename": filename, "size": size})
    display_and_log(colored("system", f"[{pretty_ts(frame_offer['ts'])}] (FILE OFFER SENT) to {to}: {filename} ({size} bytes) offer_id={offer_id}"))
    log_line(f"SENT_FRAME {json.dumps(frame_offer)}")
    # read and write sent copy to SENT_DIR to simulate transfer
    sent_copy = SENT_DIR / f"sent_{offer_id}_{filename}"
    with open(p, "rb") as fin, open(sent_copy, "wb") as fout:
        chunk_count = 0
        while True:
            chunk = fin.read(4096)
            if not chunk:
                break
            chunk_b64 = base64.urlsafe_b64encode(chunk).decode().rstrip("=")
            frame_chunk = build_frame("FILE_CHUNK", USER_ID, to, {"offer_id": offer_id, "chunk": chunk_b64})
            # simulate sending chunk (local echo suppressed for chunks, we log)
            log_line(f"SENT_FRAME {json.dumps({'type':'FILE_CHUNK','offer_id':offer_id,'len':len(chunk)})}")
            fout.write(chunk)
            chunk_count += 1
    frame_end = build_frame("FILE_END", USER_ID, to, {"offer_id": offer_id})
    display_and_log(colored("system", f"[{pretty_ts(frame_end['ts'])}] (FILE SENT) {filename} -> saved as {sent_copy} (chunks={chunk_count})"))
    log_line(f"SENT_FRAME {json.dumps(frame_end)}")

def cmd_history():
    print("\n--- History (last {}) ---".format(SCROLLBACK))
    for line in list(scrollback)[-SCROLLBACK:]:
        print(line)
    print("--- end history ---\n")

def cmd_simulate(args: list[str]):
    if not args:
        print("simulate requires arguments. See /help")
        return
    typ = args[0]
    if typ == "dm":
        if len(args) < 3:
            print("usage: /simulate dm <from> <text>")
            return
        frm = args[1]
        text = " ".join(args[2:])
        ciphertext = encrypt_sim(text.encode("utf-8"), USER_ID)
        payload = {"ciphertext": ciphertext}
        frame = build_frame("DM", frm, USER_ID, payload)
        # allow manual injection of invalidsig by putting --invalidsig in text
        if "--invalidsig" in text:
            # manufacture a bad signature
            frame["sig"] = "invalidsig"
        display_incoming(frame)
    elif typ == "all":
        if len(args) < 3:
            print("usage: /simulate all <from> <text>")
            return
        frm = args[1]
        text = " ".join(args[2:])
        ciphertext = encrypt_sim(text.encode("utf-8"), "group")
        payload = {"ciphertext": ciphertext}
        frame = build_frame("BROADCAST", frm, None, payload)
        if "--invalidsig" in text:
            frame["sig"] = "invalidsig"
        display_incoming(frame)
    elif typ == "error":
        msg = " ".join(args[1:]) if len(args) > 1 else "simulated error"
        frame = {"type": "ERROR", "from": "system", "to": USER_ID, "ts": now_iso(), "payload": {"message": msg}, "sig": ""}
        display_incoming(frame)
    elif typ == "file_offer":
        if len(args) < 3:
            print("usage: /simulate file_offer <from> <filename> [size]")
            return
        frm = args[1]
        filename = args[2]
        size = int(args[3]) if len(args) > 3 else 1234
        payload = {"offer_id": base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("="),
                   "filename": filename, "size": size}
        frame = {"type": "FILE_OFFER", "from": frm, "to": USER_ID, "ts": now_iso(), "payload": payload, "sig": ""}
        display_incoming(frame)
    else:
        print("Unknown simulate type. See /help")

# -------------------------
# Input loop (async)
# -------------------------
async def input_loop():
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=1)
    print(colored("system", f"Standalone CLI running as '{USER_ID}'. Type /help for commands."))
    while True:
        try:
            line = await loop.run_in_executor(executor, lambda: input("> ").strip())
            if not line:
                continue
            if line.startswith("/"):
                parts = line.split()
                cmd = parts[0].lower()
                if cmd == "/help":
                    cmd_help()
                elif cmd == "/list":
                    cmd_list()
                elif cmd == "/tell":
                    if len(parts) < 3:
                        print("Usage: /tell <user> <text>")
                        continue
                    to = parts[1]
                    text = " ".join(parts[2:])
                    cmd_tell(to, text)
                elif cmd == "/all":
                    if len(parts) < 2:
                        print("Usage: /all <text>")
                        continue
                    text = " ".join(parts[1:])
                    cmd_all(text)
                elif cmd == "/file":
                    if len(parts) < 3:
                        print("Usage: /file <user> <path>")
                        continue
                    to = parts[1]
                    path = " ".join(parts[2:])
                    cmd_file(to, path)
                elif cmd == "/history":
                    cmd_history()
                elif cmd == "/simulate":
                    cmd_simulate(parts[1:])
                elif cmd == "/quit":
                    print("Goodbye.")
                    return
                else:
                    print(f"Unknown command: {cmd} — try /help")
            else:
                # treat as broadcast
                cmd_all(line)
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")
            return
        except Exception as e:
            print(colored("error", f"Input loop error: {e}"))
            log_line(f"INPUT_ERROR {e}")

# -------------------------
# Main
# -------------------------
def main():
    # startup note
    log_line(f"CLIENT_START user={USER_ID}")
    try:
        asyncio.run(input_loop())
    finally:
        log_line("CLIENT_EXIT")

if __name__ == "__main__":
    main()
