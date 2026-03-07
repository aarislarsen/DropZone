"""
FileDrop — async WebSocket signaling server
Python 3.11+, aiohttp

Run:
    python server.py
    python server.py --host 0.0.0.0 --port 8080

Env vars (or .env file):
    HOST              0.0.0.0
    PORT              8080
    SESSION_TTL       600        seconds of inactivity before session auto-closes
    JOIN_WINDOW       60         seconds from creation during which new peers may join
    TURN_URL          turns:your-server:5349
    TURN_SECRET       your-coturn-static-auth-secret  (RFC 5766 long-term credential)
    TURN_REALM        your.domain
    TRUSTED_PROXY     1          set if behind nginx/caddy to respect X-Forwarded-For

Security model:
    - File bytes never touch the server; only WebRTC signaling is relayed.
    - Text-share messages are relayed as AES-GCM ciphertext. The server sees only
      opaque base64 blobs and cannot read plaintext.
    - The emoji sequence is chosen by the creator client-side and never sent to
      the server. The server stores only a random salt and the creator's ECDH
      public key to support joiner key derivation.
    - Session join is restricted to JOIN_WINDOW seconds after creation.
    - After the window closes, only IP addresses that connected during the window
      may maintain WebSocket connections in that session.
    - TURN credentials use HMAC-SHA1 with time-limited usernames per RFC 5766.
"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import argparse
from pathlib import Path

from aiohttp import web, WSMsgType

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("filedrop")
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

# ── Config ────────────────────────────────────────────────────────────────────
def load_env():
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

load_env()

HOST        = os.environ.get("HOST", "0.0.0.0")
PORT        = int(os.environ.get("PORT", "8080"))
SESSION_TTL = int(os.environ.get("SESSION_TTL", "600"))
JOIN_WINDOW = int(os.environ.get("JOIN_WINDOW", "60"))
TURN_URL    = os.environ.get("TURN_URL", "")
TURN_SECRET = os.environ.get("TURN_SECRET", "")
TURN_REALM  = os.environ.get("TURN_REALM", "")

# ── Session name generation ───────────────────────────────────────────────────
# 50 × 50 = 2,500 human-readable names. Session identity is a 128-bit random ID.
ADJECTIVES = [
    "amber","ancient","arctic","azure","blazing","bold","brass","broken",
    "calm","chrome","cobalt","coral","cosmic","crimson","cryptic","dark",
    "dawn","distant","dusk","ember","frozen","gilded","glacial","golden",
    "hollow","indigo","iron","jade","lunar","magnetic","marble","misty",
    "molten","obsidian","onyx","opal","phantom","prismatic","runic","scarlet",
    "silent","silver","slate","solar","spectral","stormy","tidal","velvet",
    "void","wild",
]
NOUNS = [
    "albatross","axolotl","badger","binturong","capybara","cassowary","cipher",
    "condor","crane","dhole","falcon","firefly","gecko","goshawk","ibis",
    "jackal","kestrel","kingfisher","komodo","lemur","lynx","manta","marmot",
    "marten","narwhal","ocelot","orca","osprey","otter","pangolin","puffin",
    "quetzal","quokka","raven","saiga","serval","sunbear","tapir","tardigrade",
    "thylacine","toucan","viper","wanderer","waxwing","wolverine","wombat",
    "wren","xenops","yak",
]

def generate_session_name() -> str:
    return f"{secrets.choice(ADJECTIVES)}-{secrets.choice(NOUNS)}"

def generate_session_id() -> str:
    # 128-bit random hex — ~3.4 × 10^38 combinations, unguessable
    return secrets.token_hex(16).upper()

def generate_peer_id() -> str:
    return secrets.token_hex(8)

def generate_salt() -> str:
    # 32-byte random salt for client-side PBKDF2; hex-encoded for JSON
    return secrets.token_hex(32)

# ── TURN credential generation ────────────────────────────────────────────────
def get_turn_config() -> list[dict]:
    """
    Generate time-limited TURN credentials using coturn's static-auth-secret
    mechanism (RFC 5766 long-term credential variant).

    Algorithm:
        username  = str(unix_expiry_timestamp)
        password  = base64( HMAC-SHA1(static_secret, username) )

    Python 3 uses hmac.new(key, msg, digestmod) — note this is the module-level
    function, not a method. digestmod must be specified explicitly.
    """
    if not TURN_URL or not TURN_SECRET:
        return []

    expiry   = int(time.time()) + 3600          # valid for 1 hour
    username = str(expiry)
    mac      = hmac.new(
        key       = TURN_SECRET.encode("utf-8"),
        msg       = username.encode("utf-8"),
        digestmod = hashlib.sha1,
    )
    credential = base64.b64encode(mac.digest()).decode("utf-8")

    entry: dict = {
        "urls":       TURN_URL,
        "username":   username,
        "credential": credential,
    }
    if TURN_REALM:
        entry["credentialType"] = "password"
    return [entry]

# ── Session / Peer state ──────────────────────────────────────────────────────
class Peer:
    def __init__(self, peer_id: str, ws: web.WebSocketResponse, remote_ip: str):
        self.peer_id   = peer_id
        self.ws        = ws
        self.remote_ip = remote_ip
        self.session_id: str | None = None

class Session:
    def __init__(self, session_id: str, creator_ip: str):
        self.session_id    = session_id
        self.name          = generate_session_name()
        self.salt          = generate_salt()
        # Creator's ephemeral ECDH public key (hex-encoded raw bytes, P-256).
        # Set by 'set-ecdh-pub' after creator picks emoji. Never derivable by server.
        self.creator_pub: str | None = None
        self.peers:       dict[str, Peer] = {}
        # IPs allowed to remain connected after join window closes
        self.allowed_ips: set[str] = {creator_ip}
        self.created_at   = time.time()
        self.last_activity= time.time()
        self.locked        = False   # True once join window expires

    def join_window_open(self) -> bool:
        return (not self.locked) and ((time.time() - self.created_at) < JOIN_WINDOW)

    def touch(self):
        self.last_activity = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.last_activity) > SESSION_TTL

    def public_info(self) -> dict:
        return {
            "sessionId": self.session_id,
            "name":      self.name,
            "peerCount": len(self.peers),
            "joinOpen":  self.join_window_open(),
        }

# Global in-memory state (no persistence by design)
sessions: dict[str, Session] = {}
peers:    dict[str, Peer]    = {}

# ── Messaging helpers ─────────────────────────────────────────────────────────
async def send(ws: web.WebSocketResponse, msg: dict):
    if not ws.closed:
        try:
            await ws.send_str(json.dumps(msg))
        except Exception:
            pass

async def broadcast(session: Session, msg: dict, exclude_id: str | None = None):
    for pid, peer in list(session.peers.items()):
        if pid != exclude_id:
            await send(peer.ws, msg)

async def relay_to(session: Session, msg: dict, target_id: str):
    target = session.peers.get(target_id)
    if target:
        await send(target.ws, msg)

def get_remote_ip(request: web.Request) -> str:
    if os.environ.get("TRUSTED_PROXY"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote or "unknown"

# ── Background tasks ──────────────────────────────────────────────────────────
async def cleanup_task():
    """
    Every 30 seconds:
    1. Lock sessions whose join window has elapsed.
    2. Disconnect peers from locked sessions whose IPs are not in the allowlist.
    3. Expire idle sessions.
    """
    while True:
        await asyncio.sleep(30)
        now = time.time()

        for session in list(sessions.values()):

            # Lock join window
            if not session.locked and (now - session.created_at) >= JOIN_WINDOW:
                session.locked = True
                log.info(
                    f"Session {session.session_id[:8]}… locked "
                    f"(allowed IPs: {session.allowed_ips})"
                )
                # Evict any peer whose IP snuck in after the window technically closed
                # but before the cleanup ran (race window is at most 30 s)
                for pid, peer in list(session.peers.items()):
                    if peer.remote_ip not in session.allowed_ips:
                        await send(peer.ws, {"type": "error", "message": "Access denied"})
                        await peer.ws.close()

            # Expire idle sessions
            if session.is_expired():
                sid = session.session_id
                sessions.pop(sid, None)
                log.info(f"Session {sid[:8]}… expired (idle)")
                for peer in list(session.peers.values()):
                    await send(peer.ws, {"type": "session-expired"})

# ── WebSocket handler ─────────────────────────────────────────────────────────
async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    remote_ip = get_remote_ip(request)

    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

    peer_id = generate_peer_id()
    peer    = Peer(peer_id, ws, remote_ip)
    peers[peer_id] = peer

    await send(ws, {
        "type":       "connected",
        "peerId":     peer_id,
        "iceServers": [
            {"urls": "stun:stun.l.google.com:19302"},
            {"urls": "stun:stun1.l.google.com:19302"},
            *get_turn_config(),
        ],
    })

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    await handle_message(peer, json.loads(msg.data))
                except (json.JSONDecodeError, KeyError):
                    pass
            elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        await cleanup_peer(peer)

    return ws

# ── Message handler ───────────────────────────────────────────────────────────
async def handle_message(peer: Peer, msg: dict):
    t = msg.get("type")

    # ── Create session ────────────────────────────────────────────────────────
    if t == "create-session":
        session_id = generate_session_id()
        session    = Session(session_id, peer.remote_ip)
        sessions[session_id] = session
        session.peers[peer.peer_id] = peer
        peer.session_id = session_id

        await send(peer.ws, {
            "type":      "session-created",
            "sessionId": session_id,
            "name":      session.name,
            "salt":      session.salt,
            "peerId":    peer.peer_id,
            # emoji is chosen client-side; server never sees it
        })
        log.info(f"Session {session_id[:8]}… created by {peer.remote_ip}")

    # ── Creator registers ephemeral ECDH public key ───────────────────────────
    elif t == "set-ecdh-pub":
        sid     = peer.session_id
        session = sessions.get(sid) if sid else None
        if not session:
            await send(peer.ws, {"type": "error", "message": "Not in a session"})
            return
        # Only the first peer (creator) may call this
        if list(session.peers.keys())[0] != peer.peer_id:
            await send(peer.ws, {"type": "error", "message": "Only session creator may set ECDH pub"})
            return
        pub = msg.get("ecdhPub", "")
        if not pub or len(pub) > 512:
            await send(peer.ws, {"type": "error", "message": "Invalid ECDH public key"})
            return
        session.creator_pub = pub
        await send(peer.ws, {"type": "ecdh-pub-set"})
        log.info(f"Session {sid[:8]}… ECDH pub registered, join window open for {JOIN_WINDOW}s")

    # ── List open sessions ────────────────────────────────────────────────────
    elif t == "list-sessions":
        active = [
            s.public_info()
            for s in sessions.values()
            if not s.is_expired() and s.creator_pub is not None and s.join_window_open()
        ]
        await send(peer.ws, {"type": "sessions-list", "sessions": active})

    # ── Joiner fetches salt + creator pub before entering emoji ───────────────
    elif t == "get-session-params":
        sid     = msg.get("sessionId", "").upper()
        session = sessions.get(sid)
        if not session:
            await send(peer.ws, {"type": "error", "message": "Session not found"})
            return
        if not session.join_window_open():
            await send(peer.ws, {"type": "error", "message": "Join window closed"})
            return
        if not session.creator_pub:
            await send(peer.ws, {"type": "error", "message": "Session not ready"})
            return
        await send(peer.ws, {
            "type":       "session-params",
            "sessionId":  sid,
            "name":       session.name,
            "salt":       session.salt,
            "creatorPub": session.creator_pub,
        })

    # ── Join session ──────────────────────────────────────────────────────────
    elif t == "join-session":
        sid     = msg.get("sessionId", "").upper()
        session = sessions.get(sid)
        if not session:
            await send(peer.ws, {"type": "error", "message": "Session not found"})
            return
        if not session.join_window_open() and peer.remote_ip not in session.allowed_ips:
            await send(peer.ws, {"type": "error", "message": "Join window closed"})
            return
        if not session.creator_pub:
            await send(peer.ws, {"type": "error", "message": "Session not ready"})
            return

        joiner_pub = msg.get("ecdhPub", "")
        if not joiner_pub or len(joiner_pub) > 512:
            await send(peer.ws, {"type": "error", "message": "Missing ECDH public key"})
            return

        session.peers[peer.peer_id] = peer
        session.allowed_ips.add(peer.remote_ip)
        peer.session_id = sid
        session.touch()

        existing = [pid for pid in session.peers if pid != peer.peer_id]
        await send(peer.ws, {
            "type":      "session-joined",
            "sessionId": sid,
            "name":      session.name,
            "peerId":    peer.peer_id,
            "peers":     existing,
        })
        # Relay joiner's ECDH pub to creator so creator can compute shared secret
        await broadcast(session, {
            "type":    "peer-joined",
            "peerId":  peer.peer_id,
            "ecdhPub": joiner_pub,
        }, exclude_id=peer.peer_id)
        log.info(f"Peer {peer.peer_id[:8]}… joined {sid[:8]}… from {peer.remote_ip}")

    # ── Leave ─────────────────────────────────────────────────────────────────
    elif t == "leave-session":
        await cleanup_peer(peer)

    # ── WebRTC signaling — relayed verbatim ───────────────────────────────────
    elif t in ("offer", "answer", "ice-candidate"):
        sid     = peer.session_id
        session = sessions.get(sid) if sid else None
        if not session:
            return
        session.touch()
        target_id = msg.get("targetId")
        if target_id:
            await relay_to(session, {**msg, "fromId": peer.peer_id}, target_id)

    # ── File announce — metadata only ─────────────────────────────────────────
    elif t == "file-announce":
        sid     = peer.session_id
        session = sessions.get(sid) if sid else None
        if session:
            session.touch()
            await broadcast(session, {
                "type":   "file-announce",
                "fromId": peer.peer_id,
                "files":  msg.get("files", []),
            }, exclude_id=peer.peer_id)

    # ── File accept / reject ──────────────────────────────────────────────────
    elif t in ("file-accept", "file-reject"):
        sid     = peer.session_id
        session = sessions.get(sid) if sid else None
        if session:
            await relay_to(session, {"type": t, "fromId": peer.peer_id}, msg.get("targetId", ""))

    # ── Text share — relayed as opaque AES-GCM ciphertext ────────────────────
    elif t == "text-share":
        sid     = peer.session_id
        session = sessions.get(sid) if sid else None
        if not session:
            return
        session.touch()
        ct = msg.get("ct", "")   # base64(AES-GCM ciphertext + tag)
        iv = msg.get("iv", "")   # base64(12-byte GCM nonce)
        if not ct or not iv:
            await send(peer.ws, {"type": "error", "message": "Malformed text-share"})
            return
        if len(ct) > 200_000:
            await send(peer.ws, {"type": "error", "message": "Ciphertext too large"})
            return
        # Server relays without decrypting — operator cannot read content
        await broadcast(session, {
            "type":   "text-share",
            "fromId": peer.peer_id,
            "ct":     ct,
            "iv":     iv,
        }, exclude_id=peer.peer_id)

# ── Peer cleanup ──────────────────────────────────────────────────────────────
async def cleanup_peer(peer: Peer):
    peers.pop(peer.peer_id, None)
    sid = peer.session_id
    if not sid:
        return
    session = sessions.get(sid)
    if not session:
        return
    session.peers.pop(peer.peer_id, None)
    peer.session_id = None
    await broadcast(session, {"type": "peer-left", "peerId": peer.peer_id})
    if not session.peers:
        sessions.pop(sid, None)
        log.info(f"Session {sid[:8]}… removed (empty)")
    else:
        log.info(f"Peer {peer.peer_id[:8]}… left {sid[:8]}…")

# ── HTTP ──────────────────────────────────────────────────────────────────────
async def index_handler(request: web.Request) -> web.Response:
    return web.FileResponse(Path(__file__).parent / "static" / "index.html")

def create_app() -> web.Application:
    app = web.Application()
    static_dir = Path(__file__).parent / "static"
    app.router.add_get("/ws",  ws_handler)
    app.router.add_get("/",    index_handler)
    app.router.add_static("/", static_dir, show_index=False)
    async def start_cleanup(app):
        asyncio.ensure_future(cleanup_task())
    app.on_startup.append(start_cleanup)
    return app

# ── coturn setup ──────────────────────────────────────────────────────────────
def check_or_install_coturn():
    """
    Check whether coturn is installed and TURN is configured.
    - If TURN_URL is already set, nothing to do.
    - If coturn is missing and we are not root, print a tip and return.
    - If coturn is missing and we are root, offer an interactive install.
    """
    if TURN_URL:
        return  # Already configured

    coturn_present = shutil.which("turnserver") is not None

    if coturn_present:
        log.warning(
            "coturn is installed but TURN_URL is not configured — "
            "file transfer may fail between peers on different networks. "
            "Set TURN_URL / TURN_SECRET / TURN_REALM in a .env file."
        )
        return

    log.warning(
        "coturn is not installed — file transfer may fail between peers "
        "on different networks."
    )

    if os.geteuid() != 0:
        print(
            f"\n  Tip: re-run with sudo to automatically install and configure coturn:\n"
            f"  sudo python3 {Path(__file__).name}\n"
        )
        return

    # ── Running as root: offer to install ─────────────────────────────────────
    try:
        answer = input("\nInstall and configure coturn now? [y/N]: ").strip().lower()
    except EOFError:
        return
    if answer != "y":
        return

    try:
        domain = input("Public IP or domain for TURN (e.g. 74.234.178.33): ").strip()
    except EOFError:
        return
    if not domain:
        log.warning("No domain entered — skipping coturn setup.")
        return

    secret = secrets.token_hex(32)

    log.info("Installing coturn…")
    try:
        subprocess.run(["apt-get", "install", "-y", "coturn"], check=True)
    except Exception as e:
        log.error(f"apt-get install failed: {e}")
        return

    Path("/etc/turnserver.conf").write_text(
        f"listening-port=3478\n"
        f"tls-listening-port=5349\n"
        f"fingerprint\n"
        f"lt-cred-mech\n"
        f"use-auth-secret\n"
        f"static-auth-secret={secret}\n"
        f"realm={domain}\n"
        f"no-multicast-peers\n"
        f"no-cli\n"
        f"min-port=49152\n"
        f"max-port=65535\n"
    )

    defaults = Path("/etc/default/coturn")
    if defaults.exists():
        defaults.write_text(
            defaults.read_text().replace("#TURNSERVER_ENABLED=1", "TURNSERVER_ENABLED=1")
        )

    try:
        subprocess.run(["systemctl", "enable", "--now", "coturn"], check=True)
    except Exception as e:
        log.warning(f"Could not start coturn service: {e}")

    # Write TURN vars into .env, preserving any existing entries
    env_path = Path(__file__).parent / ".env"
    kept = []
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.split("=")[0].strip() not in ("TURN_URL", "TURN_SECRET", "TURN_REALM"):
                kept.append(line)
    kept += [
        f"TURN_URL=turn:{domain}:3478",
        f"TURN_SECRET={secret}",
        f"TURN_REALM={domain}",
    ]
    env_path.write_text("\n".join(kept) + "\n")

    log.info(f"coturn installed and configured (realm: {domain}).")
    print(
        "\n  Open the following ports in your firewall / Azure NSG:\n"
        "\n"
        "  ┌──────────────────┬─────────────┬──────────────────────────────┐\n"
        "  │ Port             │ Protocol    │ Purpose                      │\n"
        "  ├──────────────────┼─────────────┼──────────────────────────────┤\n"
        "  │ 3478             │ UDP + TCP   │ STUN / TURN                  │\n"
        "  │ 5349             │ UDP + TCP   │ TURNS (TURN over TLS)        │\n"
        "  │ 49152 – 65535    │ UDP         │ TURN relay ports             │\n"
        "  └──────────────────┴─────────────┴──────────────────────────────┘\n"
        "\n"
        "  coturn is running. Restart server.py (without sudo) to start\n"
        "  FileDrop with TURN enabled.\n"
    )
    sys.exit(0)

# ── TLS ───────────────────────────────────────────────────────────────────────
def _make_ssl_context_openssl(cert_path: Path, key_path: Path) -> "ssl.SSLContext | None":
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(key_path), "-out", str(cert_path),
             "-days", "365", "-nodes", "-subj", "/CN=filedrop"],
            check=True, capture_output=True,
        )
        key_path.chmod(0o600)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        log.info(f"Generated self-signed TLS certificate (openssl) → {cert_path.name}")
        return ctx
    except Exception as e:
        log.error(f"SSL setup failed: {e}")
        return None

def make_ssl_context() -> "ssl.SSLContext | None":
    cert_path = Path(__file__).parent / "filedrop-cert.pem"
    key_path  = Path(__file__).parent / "filedrop-key.pem"

    # Reuse existing certificate if present
    if cert_path.exists() and key_path.exists():
        try:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(str(cert_path), str(key_path))
            log.info(f"Loaded existing TLS certificate ({cert_path.name})")
            return ctx
        except Exception as e:
            log.warning(f"Existing certificate could not be loaded ({e}) — regenerating")

    # Generate and save a new certificate
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "filedrop")])
        now  = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        key_path.chmod(0o600)
        log.info(f"Generated self-signed TLS certificate → {cert_path.name}")
    except ImportError:
        log.warning("'cryptography' package not found — falling back to openssl")
        return _make_ssl_context_openssl(cert_path, key_path)
    except Exception as e:
        log.error(f"SSL certificate generation failed: {e}")
        return None

    try:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        return ctx
    except Exception as e:
        log.error(f"SSL context creation failed: {e}")
        return None

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FileDrop signaling server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--no-ssl", action="store_true", help="Disable TLS (not recommended)")
    args = parser.parse_args()
    check_or_install_coturn()
    ssl_ctx = None if args.no_ssl else make_ssl_context()
    proto   = "https" if ssl_ctx else "http"
    log.info(f"FileDrop on {proto}://{args.host}:{args.port}  TTL={SESSION_TTL}s  window={JOIN_WINDOW}s  TURN={'yes' if TURN_URL else 'no'}")
    if ssl_ctx is None and not args.no_ssl:
        log.warning("Running without TLS — Web Crypto API will be unavailable in browsers")
    web.run_app(create_app(), host=args.host, port=args.port, print=None, ssl_context=ssl_ctx)
