import asyncio
import hashlib
import hmac
import json
import os
import shutil
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Header, Depends, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc
from argon2 import PasswordHasher
from models import Session as SessionModel
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta, timezone
from schema import (
    AuthRequest,
    CallActionRequest,
    CallInitiateRequest,
    ChatRequest,
    MessageRequest,
    MediaInitRequest,
    PublishRequest,
    PKeyResponse,
    SignupRequest,
    EpochRequest,
)
import secrets

from models import init_db, SessionLocal, User, Chat, Message, UserKey, ChatEpoch, MediaAttachment, PendingUpload, Call

# ── Media storage constants ───────────────────────────────────────────────────

MEDIA_DIR = Path("./media")
MAX_CHUNK_SIZE  = 5   * 1024 * 1024   # 5 MiB per chunk
MAX_TOTAL_SIZE  = 200 * 1024 * 1024   # 200 MiB per file

app = FastAPI()

app.mount("/app", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ph = PasswordHasher()

# ── WebSocket connection manager ──────────────────────────────────────

class ConnectionManager:
    """Tracks active WebSocket connections per chat."""

    def __init__(self):
        # chat_id -> dict[user_id, WebSocket]
        self.active: dict[int, dict[int, WebSocket]] = {}

    async def connect(self, chat_id: int, user_id: int, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(chat_id, {})[user_id] = ws

    def disconnect(self, chat_id: int, user_id: int):
        chat_conns = self.active.get(chat_id)
        if chat_conns:
            chat_conns.pop(user_id, None)
            if not chat_conns:
                del self.active[chat_id]

    async def broadcast(self, chat_id: int, payload: dict, exclude_user_id: int | None = None):
        """Send a JSON message to every user connected to *chat_id*."""
        chat_conns = self.active.get(chat_id)
        if not chat_conns:
            return
        data = json.dumps(payload)
        stale: list[int] = []
        for uid, ws in chat_conns.items():
            if uid == exclude_user_id:
                continue
            try:
                await ws.send_text(data)
            except Exception:
                stale.append(uid)
        for uid in stale:
            chat_conns.pop(uid, None)

manager = ConnectionManager()


# ── Presence manager (one WS per logged-in user, for push notifications) ──────

class PresenceManager:
    """Tracks a single presence WebSocket per user_id.

    Used exclusively for push notifications that must reach a user regardless
    of which chat (if any) they have open — e.g. incoming call invites.
    """

    def __init__(self):
        # user_id -> WebSocket
        self.sockets: dict[int, WebSocket] = {}

    async def connect(self, user_id: int, ws: WebSocket):
        await ws.accept()
        self.sockets[user_id] = ws

    def disconnect(self, user_id: int):
        self.sockets.pop(user_id, None)

    async def send(self, user_id: int, payload: dict) -> bool:
        """Send JSON to the user's presence socket.  Returns True on success."""
        ws = self.sockets.get(user_id)
        if not ws:
            return False
        try:
            await ws.send_text(json.dumps(payload))
            return True
        except Exception:
            self.sockets.pop(user_id, None)
            return False


# ── Call signaling manager (at most 2 parties per call) ───────────────────────

class CallSignalingManager:
    """Tracks signaling WebSocket connections for active calls.

    call_id -> {user_id: WebSocket}
    """

    def __init__(self):
        self.calls: dict[str, dict[int, WebSocket]] = {}

    async def connect(self, call_id: str, user_id: int, ws: WebSocket):
        await ws.accept()
        self.calls.setdefault(call_id, {})[user_id] = ws

    def disconnect(self, call_id: str, user_id: int):
        conns = self.calls.get(call_id)
        if conns:
            conns.pop(user_id, None)
            if not conns:
                del self.calls[call_id]

    async def broadcast(self, call_id: str, payload: dict, exclude_user_id: int | None = None):
        conns = self.calls.get(call_id)
        if not conns:
            return
        data = json.dumps(payload)
        for uid, ws in list(conns.items()):
            if uid == exclude_user_id:
                continue
            try:
                await ws.send_text(data)
            except Exception:
                conns.pop(uid, None)


# ── Call audio relay manager ──────────────────────────────────────────────────

class CallAudioManager:
    """Binary audio relay: forwards encrypted audio frames between two peers.

    call_id -> {user_id: WebSocket}
    Each binary frame received from one party is forwarded verbatim to the other.
    """

    def __init__(self):
        self.calls: dict[str, dict[int, WebSocket]] = {}

    async def connect(self, call_id: str, user_id: int, ws: WebSocket):
        await ws.accept()
        self.calls.setdefault(call_id, {})[user_id] = ws

    def disconnect(self, call_id: str, user_id: int):
        conns = self.calls.get(call_id)
        if conns:
            conns.pop(user_id, None)
            if not conns:
                del self.calls[call_id]

    async def relay(self, call_id: str, sender_id: int, data: bytes):
        """Forward raw bytes to the OTHER party in the call."""
        conns = self.calls.get(call_id, {})
        for uid, ws in list(conns.items()):
            if uid == sender_id:
                continue
            try:
                await ws.send_bytes(data)
            except Exception:
                conns.pop(uid, None)


presence  = PresenceManager()
call_sig  = CallSignalingManager()
call_audio = CallAudioManager()

# ── Startup ───────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    # Background task: purge expired pending uploads every hour.
    asyncio.ensure_future(_purge_expired_uploads())
    # Background task: delete expired ephemeral messages every 5 seconds.
    asyncio.ensure_future(_expire_messages())


async def _purge_expired_uploads():
    """Periodically delete pending upload sessions that have passed their expiry."""
    while True:
        await asyncio.sleep(3600)
        try:
            db: Session = SessionLocal()
            try:
                stale = (
                    db.query(PendingUpload)
                    .filter(PendingUpload.expires_at < datetime.now(timezone.utc))
                    .all()
                )
                for pu in stale:
                    shutil.rmtree(pu.storage_dir, ignore_errors=True)
                    db.delete(pu)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass  # Never crash the background task

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def _expire_messages():
    """Periodically delete messages whose expires_at has passed and notify WS clients."""
    while True:
        await asyncio.sleep(5)
        try:
            db: Session = SessionLocal()
            try:
                now = datetime.now(timezone.utc)
                expired = (
                    db.query(Message)
                    .filter(Message.expires_at.isnot(None), Message.expires_at <= now)
                    .all()
                )
                for msg in expired:
                    # Notify connected clients before deleting
                    asyncio.ensure_future(manager.broadcast(
                        msg.chat_id,
                        {"type": "message_deleted", "message_id": msg.id},
                    ))
                    # Clean up linked media blob
                    if msg.media_id:
                        att = (
                            db.query(MediaAttachment)
                            .filter(MediaAttachment.id == msg.media_id)
                            .one_or_none()
                        )
                        if att:
                            blob = Path(att.storage_path)
                            try:
                                if blob.exists():
                                    blob.unlink()
                                parent = blob.parent
                                if parent.exists() and not any(parent.iterdir()):
                                    parent.rmdir()
                            except OSError:
                                pass
                            db.delete(att)
                    db.delete(msg)
                if expired:
                    db.commit()
            finally:
                db.close()
        except Exception:
            pass  # Never crash the background task

try:
    SERVER_KEY = "pls get job".encode("utf-8")
except Exception:
    raise RuntimeError("SERVER_KEY environment variable must be set")

async def require_auth(
    authorization: str = Header(...),
    db: Session = Depends(get_db),
    device_Id: str = Header(..., alias="X-Device-ID")
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = None

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.session_token_hash == token_hash,
            SessionModel.expires_at > datetime.now(timezone.utc),
            SessionModel.device_id == device_Id,
        )
        .one_or_none()
    )

    if not session:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user = (
        db.query(User)
        .filter(User.id == session.user_id)
        .one_or_none()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return user

@app.get("/")
async def read_root():
    return {"ping": "pong"}


# Authentication endpoints
@app.post("/auth/signup", status_code=201)
async def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    existing_user = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    password_hash = ph.hash(payload.password)

    user = User(
        username=payload.username,
        password_hash=password_hash,
    )

    db.add(user)
    db.flush()  # get user.id without committing

    user_key = UserKey(
        user_id=user.id,
        identity_pub=payload.identity_pub,
        encrypted_identity_priv=payload.encrypted_identity_priv,
        kdf_salt=payload.kdf_salt,
        aead_nonce=payload.aead_nonce,
    )

    db.add(user_key)
    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
    }
    

@app.post("/auth/login")
async def login(
    payload: AuthRequest, 
    db: Session = Depends(get_db),
    device_Id: str = Header(..., alias="X-Device-ID"),
    user_Agent: str | None = Header(None),
):
    user = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        ph.verify(user.password_hash, payload.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)

    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    session = SessionModel(
        user_id=user.id,
        device_id=device_Id,
        session_token_hash=token_hash,
        user_agent=user_Agent,
        last_accessed=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )

    db.add(session)
    db.commit()

    return {"token": token}

@app.post("/auth/logout")
async def logout(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    session = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id)
        .one_or_none()
    )

    db.delete(session)
    db.commit()

    return {"status": "logged out"}

@app.get("/auth/keyblob")
async def get_encrypted_key_blob(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    user_key = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if not user_key:
        raise HTTPException(
            status_code=404,
            detail="Identity key material not found",
        )

    return {
        "identity_pub": user_key.identity_pub,
        "encrypted_identity_priv": user_key.encrypted_identity_priv,
        "kdf_salt": user_key.kdf_salt,
        "aead_nonce": user_key.aead_nonce,
    }

@app.get("/auth/me")
async def get_me(user: User = Depends(require_auth)):
        return {"id": user.id, "username": user.username}

# Account endpoints
@app.get("/users/sessions")
async def list_sessions(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    authorization: str = Header(...),
    device_id: str = Header(..., alias="X-Device-ID"),
):
    token = authorization.removeprefix("Bearer ").strip()
    current_token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id)
        .all()
    )

    return [
        {
            "id": s.id,
            "device_id": s.device_id,
            "user_agent": s.user_agent,
            "last_accessed": s.last_accessed,
            "created_at": s.created_at,
            "expires_at": s.expires_at,
            "current": (
                s.session_token_hash == current_token_hash and
                s.device_id == device_id
            ),
        }
        for s in sessions
    ]

@app.delete("/users/sessions/revoke/{session_id}")
async def revoke_session(
    session_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.id == session_id,
            SessionModel.user_id == user.id,
        )
        .one_or_none()
    )

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete(session)
    db.commit()

    return {"status": "revoked"}

@app.delete("/users/sessions/revoke_other")
async def revoke_other(
    user: User = Depends(require_auth),
    authorization: str = Header(...),
    device_id: str = Header(..., alias="X-Device-ID"),
    db: Session = Depends(get_db),
):
    token = authorization.removeprefix("Bearer ").strip()
    current_token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user.id,
            ~(
                (SessionModel.session_token_hash == current_token_hash) &
                (SessionModel.device_id == device_id)
            )
        )
        .delete(synchronize_session=False)
    )

    db.commit()

    return {"status": "other sessions revoked"}

@app.post("/user/pkey/publish", status_code=201)
async def publish_public_key(
    payload: PublishRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Public key already published",
        )

    user_key = UserKey(
        user_id=user.id,
        identity_pub=payload.identity_pub,
        encrypted_identity_priv=payload.encrypted_identity_priv,
        kdf_salt=payload.kdf_salt,
        aead_nonce=payload.aead_nonce,
    )

    db.add(user_key)
    db.commit()

    return {"status": "published"}

@app.get("/user/pkey/get", response_model=PKeyResponse)
async def get_public_key(
    username: str = Query(...),
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.username == username)
        .one_or_none()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_key = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if not user_key:
        raise HTTPException(
            status_code=404,
            detail="User has not published a public key",
        )

    return {
        "username": user.username,
        "identity_pub": user_key.identity_pub,
    }

# ── WebSocket helper: authenticate from query params ─────────────────

def ws_authenticate(token: str, device_id: str, db: Session) -> User | None:
    """Validate a session token + device-id and return the User, or None."""
    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.session_token_hash == token_hash,
            SessionModel.expires_at > datetime.now(timezone.utc),
            SessionModel.device_id == device_id,
        )
        .one_or_none()
    )
    if not session:
        return None

    return db.query(User).filter(User.id == session.user_id).one_or_none()


# ── WebSocket endpoint ───────────────────────────────────────────────

@app.websocket("/chat/ws/{chat_id}")
async def chat_ws(
    websocket: WebSocket,
    chat_id: int,
    token: str = Query(...),
    device_id: str = Query(...),
):
    db: Session = SessionLocal()
    try:
        # authenticate
        user = ws_authenticate(token, device_id, db)
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        # verify membership
        chat = (
            db.query(Chat)
            .filter(
                Chat.id == chat_id,
                or_(
                    Chat.user_a_id == user.id,
                    Chat.user_b_id == user.id,
                ),
            )
            .one_or_none()
        )
        if not chat:
            await websocket.close(code=4004, reason="Chat not found")
            return

        await manager.connect(chat_id, user.id, websocket)

        # send initial history (last 50 messages)
        messages = (
            db.query(Message)
            .filter(Message.chat_id == chat_id)
            .order_by(desc(Message.id))
            .limit(50)
            .all()
        )
        messages.reverse()

        history_payload = [
            {
                "id": m.id,
                "sender_id": m.sender_id,
                "epoch_id": m.epoch_id,
                "reply_id": m.reply_id,
                "media_id": m.media_id,
                "ciphertext": m.ciphertext,
                "nonce": m.nonce,
                "created_at": m.created_at.isoformat(),
                "expires_at": m.expires_at.isoformat() if m.expires_at else None,
            }
            for m in messages
        ]
        next_cursor = messages[0].id if messages else None

        await websocket.send_text(json.dumps({
            "type": "history",
            "messages": history_payload,
            "next_cursor": next_cursor,
        }))

        # keep connection alive – listen for client pings / close
        while True:
            try:
                data = await websocket.receive_text()
                # clients may send {"type":"ping"} to keep alive
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        manager.disconnect(chat_id, user.id)
        db.close()


# Chat endpoints
@app.get("/chat/list")
async def chat_list(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    
    chats = (
        db.query(Chat)
        .filter(
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id
            )
        )
        .all()
    )

    result = []

    for chat in chats:
        other_user_id = (
            chat.user_b_id if chat.user_a_id == user.id else chat.user_a_id
        )

        other_user = (
            db.query(User)
            .filter(User.id == other_user_id)
            .one()
        )

        result.append({
            "chat_id": chat.id,
            "with_user": other_user.username,
        })

    return result

@app.get("/chat/fetch/{chat_id}")
async def fetch_chat(
    chat_id: int,
    before_id: int | None = Query(None),
    limit: int = Query(50, le=100),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    query = db.query(Message).filter(Message.chat_id == chat_id)

    if before_id is not None:
        query = query.filter(Message.id < before_id)

    messages = (
        query.order_by(desc(Message.id))
        .limit(limit)
        .all()
    )

    messages.reverse()

    message_payload = [
        {
            "id": m.id,
            "sender_id": m.sender_id,
            "epoch_id": m.epoch_id,
            "reply_id": m.reply_id,
            "media_id": m.media_id,
            "ciphertext": m.ciphertext,
            "nonce": m.nonce,
            "created_at": m.created_at,
            "expires_at": m.expires_at.isoformat() if m.expires_at else None,
        }
        for m in messages
    ]

    next_cursor = messages[0].id if messages else None

    return {
        "messages": message_payload,
        "next_cursor": next_cursor,
    }


@app.get("/chat/{chat_id}/{epoch_id}/fetch")
async def fetch_epoch(
    chat_id: int,
    epoch_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    epoch = (
        db.query(ChatEpoch)
        .filter(
            ChatEpoch.id == epoch_id,
            ChatEpoch.chat_id == chat_id,
        )
        .one_or_none()
    )

    if not epoch:
        raise HTTPException(status_code=404, detail="Epoch not found")

    is_user_a = chat.user_a_id == user.id

    return {
        "epoch_id": epoch.id,
        "epoch_index": epoch.epoch_index,
        "wrapped_key": epoch.wrapped_key_a if is_user_a else epoch.wrapped_key_b,
    }


@app.post("/chat/create")
async def create_chat(
    payload: ChatRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    target = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    existing_chat = (
        db.query(Chat)
        .filter(
            or_(
                (Chat.user_a_id == user.id) & (Chat.user_b_id == target.id),
                (Chat.user_a_id == target.id) & (Chat.user_b_id == user.id),
            )
        )
        .one_or_none()
    )

    if existing_chat:
        return {"chat_id": existing_chat.id}

    chat = Chat(user_a_id=user.id, user_b_id=target.id)
    db.add(chat)
    db.flush()

    # create empty epoch 0 placeholder
    epoch0 = ChatEpoch(
        chat_id=chat.id,
        epoch_index=0,
        wrapped_key_a="",
        wrapped_key_b="",
    )
    db.add(epoch0)

    db.commit()

    return {"chat_id": chat.id}

@app.post("/chat/{chat_id}/epoch", status_code=201)
async def create_epoch(
    chat_id: int,
    payload: EpochRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    # rate-limit: at most one epoch every 5 seconds per chat
    # (ignore placeholder epochs with empty keys)
    recent = (
        db.query(ChatEpoch)
        .filter(
            ChatEpoch.chat_id == chat_id,
            ChatEpoch.wrapped_key_a != "",
            ChatEpoch.created_at
            > datetime.now(timezone.utc) - timedelta(seconds=5),
        )
        .count()
    )

    if recent > 0:
        raise HTTPException(status_code=429, detail="Epoch creation throttled")

    # message-count gate (rotate every 200 messages)
    msg_count = (
        db.query(func.count(Message.id))
        .filter(Message.chat_id == chat_id)
        .scalar()
    )

    if msg_count % 200 != 0:
        raise HTTPException(
            status_code=400,
            detail="Epoch rotation not allowed yet",
        )

    # serialize epoch creation
    last_epoch = (
        db.query(ChatEpoch)
        .filter(ChatEpoch.chat_id == chat_id)
        .order_by(ChatEpoch.epoch_index.desc())
        .with_for_update()
        .first()
    )

    next_index = 0 if not last_epoch else last_epoch.epoch_index + 1

    epoch = ChatEpoch(
        chat_id=chat_id,
        epoch_index=next_index,
        wrapped_key_a=payload.wrapped_key_a,
        wrapped_key_b=payload.wrapped_key_b,
    )

    db.add(epoch)
    db.commit()
    db.refresh(epoch)

    return {
        "epoch_id": epoch.id,
        "epoch_index": epoch.epoch_index,
    }

@app.post("/chat/{chat_id}/message", status_code=201)
async def message(
    chat_id: int,
    payload: MessageRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    epoch = (
        db.query(ChatEpoch)
        .filter(
            ChatEpoch.id == payload.epoch_id,
            ChatEpoch.chat_id == chat_id,
        )
        .one_or_none()
    )

    if not epoch:
        raise HTTPException(status_code=409, detail="Unknown epoch")

    latest_epoch = (
        db.query(ChatEpoch)
        .filter(ChatEpoch.chat_id == chat_id)
        .order_by(ChatEpoch.epoch_index.desc())
        .first()
    )

    if epoch.id != latest_epoch.id:
        raise HTTPException(
            status_code=409,
            detail="Stale epoch; fetch latest epoch",
        )

    if not epoch.wrapped_key_a or not epoch.wrapped_key_b:
        raise HTTPException(
            status_code=409,
            detail="Epoch not initialized",
        )

    # If a media_id is provided, verify it belongs to this chat and was uploaded by the sender.
    if payload.media_id is not None:
        attachment = (
            db.query(MediaAttachment)
            .filter(MediaAttachment.id == payload.media_id)
            .one_or_none()
        )
        if not attachment:
            raise HTTPException(status_code=404, detail="Media attachment not found")
        if attachment.chat_id != chat_id:
            raise HTTPException(status_code=409, detail="Media attachment belongs to a different chat")
        if attachment.uploader_id != user.id:
            raise HTTPException(status_code=403, detail="Media attachment was not uploaded by you")

    # Parse optional ephemeral expiry
    expires_at = None
    if payload.expires_at:
        try:
            expires_at = datetime.fromisoformat(payload.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            pass

    msg = Message(
        chat_id=chat.id,
        sender_id=user.id,
        epoch_id=payload.epoch_id,
        reply_id=payload.reply_id,
        media_id=payload.media_id,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        expires_at=expires_at,
    )

    db.add(msg)
    db.commit()
    db.refresh(msg)

    # broadcast to WebSocket subscribers of this chat
    ws_payload = {
        "type": "new_message",
        "message": {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "epoch_id": msg.epoch_id,
            "reply_id": msg.reply_id,
            "media_id": msg.media_id,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "created_at": msg.created_at.isoformat(),
            "expires_at": msg.expires_at.isoformat() if msg.expires_at else None,
        },
    }
    asyncio.ensure_future(manager.broadcast(chat_id, ws_payload))

    return {
        "id": msg.id,
        "epoch_id": msg.epoch_id,
        "media_id": msg.media_id,
        "created_at": msg.created_at,
    }


# ── Media endpoints ───────────────────────────────────────────────────────────

@app.post("/media/upload/init", status_code=201)
async def media_upload_init(
    payload: MediaInitRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Begin a chunked encrypted-media upload session.

    Validates chat membership, creates a staging directory, and returns an
    upload_id the client uses for subsequent /chunk and /finalize calls.
    The server never receives plaintext — clients must encrypt before uploading.
    """
    # Validate chat membership
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == payload.chat_id,
            or_(Chat.user_a_id == user.id, Chat.user_b_id == user.id),
        )
        .one_or_none()
    )
    if not chat:
        raise HTTPException(status_code=403, detail="Not a participant of this chat")

    upload_id = str(uuid.uuid4())
    storage_dir = MEDIA_DIR / str(payload.chat_id) / upload_id
    storage_dir.mkdir(parents=True, exist_ok=True)

    pending = PendingUpload(
        id=upload_id,
        uploader_id=user.id,
        chat_id=payload.chat_id,
        total_size=payload.total_size,
        chunk_size=payload.chunk_size,
        total_chunks=payload.total_chunks,
        chunks_received=0,
        storage_dir=str(storage_dir),
        file_type=payload.file_type,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(pending)
    db.commit()

    return {"upload_id": upload_id}


@app.put("/media/upload/{upload_id}/chunk/{chunk_index}")
async def media_upload_chunk(
    upload_id: str,
    chunk_index: int,
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Upload a single chunk (raw encrypted bytes) for an in-progress upload session."""
    pending = (
        db.query(PendingUpload)
        .filter(PendingUpload.id == upload_id)
        .one_or_none()
    )
    if not pending:
        raise HTTPException(status_code=404, detail="Upload session not found")
    if pending.uploader_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if chunk_index < 0 or chunk_index >= pending.total_chunks:
        raise HTTPException(
            status_code=400,
            detail=f"chunk_index must be 0..{pending.total_chunks - 1}",
        )

    chunk_data = await request.body()
    if not chunk_data:
        raise HTTPException(status_code=400, detail="Empty chunk body")
    if len(chunk_data) > MAX_CHUNK_SIZE:
        raise HTTPException(status_code=413, detail="Chunk exceeds 5 MiB limit")

    chunk_path = Path(pending.storage_dir) / f"chunk_{chunk_index:06d}"
    chunk_path.write_bytes(chunk_data)

    # Recount actual chunk files on disk (idempotent — handles retransmission)
    received = len(list(Path(pending.storage_dir).glob("chunk_*")))
    pending.chunks_received = received
    db.commit()

    return {
        "chunk_index": chunk_index,
        "chunks_remaining": pending.total_chunks - received,
    }


@app.post("/media/upload/{upload_id}/finalize", status_code=201)
async def media_upload_finalize(
    upload_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Assemble all chunks into a single encrypted blob and create a MediaAttachment record."""
    pending = (
        db.query(PendingUpload)
        .filter(PendingUpload.id == upload_id)
        .one_or_none()
    )
    if not pending:
        raise HTTPException(status_code=404, detail="Upload session not found")
    if pending.uploader_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    storage_dir = Path(pending.storage_dir)
    chunk_files = sorted(storage_dir.glob("chunk_*"))

    if len(chunk_files) != pending.total_chunks:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Incomplete upload: received {len(chunk_files)} of "
                f"{pending.total_chunks} chunks"
            ),
        )

    # Assemble chunks → blob
    blob_path = storage_dir / "blob"
    with blob_path.open("wb") as out:
        for cf in chunk_files:
            out.write(cf.read_bytes())
            cf.unlink()
    actual_size = blob_path.stat().st_size

    attachment = MediaAttachment(
        uploader_id=user.id,
        chat_id=pending.chat_id,
        storage_path=str(blob_path),
        total_size=actual_size,
        file_type=pending.file_type,
    )
    db.add(attachment)
    db.flush()

    media_id = attachment.id
    db.delete(pending)
    db.commit()

    return {"media_id": media_id}


@app.get("/media/{media_id}")
async def media_download(
    media_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Stream an encrypted media blob. Only chat participants may download.

    The response body is raw encrypted bytes (AES-256-GCM ciphertext).
    The decryption key lives inside the linked message ciphertext and is
    never transmitted in plaintext through the server.
    """
    attachment = (
        db.query(MediaAttachment)
        .filter(MediaAttachment.id == media_id)
        .one_or_none()
    )
    if not attachment:
        raise HTTPException(status_code=404, detail="Media not found")

    # Only participants of the linked chat may download
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == attachment.chat_id,
            or_(Chat.user_a_id == user.id, Chat.user_b_id == user.id),
        )
        .one_or_none()
    )
    if not chat:
        raise HTTPException(status_code=403, detail="Forbidden")

    blob_path = Path(attachment.storage_path)
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="Media file missing from disk")

    return FileResponse(
        path=str(blob_path),
        media_type="application/octet-stream",
        filename=f"attachment_{media_id}",
    )


@app.delete("/media/{media_id}")
async def media_delete(
    media_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Delete a media attachment and its blob from disk. Only the uploader may delete."""
    attachment = (
        db.query(MediaAttachment)
        .filter(MediaAttachment.id == media_id)
        .one_or_none()
    )
    if not attachment:
        raise HTTPException(status_code=404, detail="Media not found")
    if attachment.uploader_id != user.id:
        raise HTTPException(status_code=403, detail="Only the uploader may delete this media")

    # Remove the blob from disk
    blob_path = Path(attachment.storage_path)
    try:
        if blob_path.exists():
            blob_path.unlink()
        parent = blob_path.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
    except OSError:
        pass  # Best-effort; DB record is still removed

    # Null-out references in messages so history still renders
    (
        db.query(Message)
        .filter(Message.media_id == media_id)
        .update({"media_id": None}, synchronize_session=False)
    )

    db.delete(attachment)
    db.commit()

    return {"status": "deleted"}


# ════════════════════════════════════════════════════════════════════════════════
# VoIP — Presence, Call Management, Signaling, Audio Relay
# ════════════════════════════════════════════════════════════════════════════════

# ── Presence WebSocket ────────────────────────────────────────────────────────

@app.websocket("/user/ws")
async def user_presence_ws(
    websocket: WebSocket,
    token: str = Query(...),
    device_id: str = Query(...),
):
    """Persistent per-user presence socket.

    The TUI connects here once after login.  The server pushes:
      • {"type": "call_invite", "call_id": "...", "caller_username": "...", "initiated_at": "..."}
      • {"type": "pong"} in response to {"type": "ping"}

    No chat membership check is required — it is a user-scoped socket.
    """
    db: Session = SessionLocal()
    try:
        user = ws_authenticate(token, device_id, db)
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        await presence.connect(user.id, websocket)
        try:
            while True:
                data = await websocket.receive_text()
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
    finally:
        presence.disconnect(user.id if user else -1)
        db.close()


# ── Call REST endpoints ───────────────────────────────────────────────────────

@app.post("/call/initiate", status_code=201)
async def call_initiate(
    payload: CallInitiateRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Initiate a VoIP call to another user.

    Creates a Call row with status "ringing" and pushes a call_invite frame
    to the callee's presence WebSocket (if they are connected).
    """
    callee = (
        db.query(User)
        .filter(User.username == payload.callee_username)
        .one_or_none()
    )
    if not callee:
        raise HTTPException(status_code=404, detail="User not found")
    if callee.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot call yourself")

    import uuid as _uuid
    call_id = str(_uuid.uuid4())
    now = datetime.now(timezone.utc)

    call = Call(
        id=call_id,
        caller_id=user.id,
        callee_id=callee.id,
        chat_id=payload.chat_id,
        status="ringing",
        initiated_at=now,
    )
    db.add(call)
    db.commit()

    # Push invite to callee's presence socket (best-effort)
    asyncio.ensure_future(presence.send(callee.id, {
        "type": "call_invite",
        "call_id": call_id,
        "caller_username": user.username,
        "initiated_at": now.isoformat(),
    }))

    return {
        "call_id": call_id,
        "status": "ringing",
        "caller_username": user.username,
        "callee_username": callee.username,
    }


@app.post("/call/answer")
async def call_answer(
    payload: CallActionRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    call = db.query(Call).filter(Call.id == payload.call_id).one_or_none()
    if not call:
        raise HTTPException(status_code=404, detail="Call not found")
    if call.callee_id != user.id:
        raise HTTPException(status_code=403, detail="Only the callee may answer")
    if call.status != "ringing":
        raise HTTPException(status_code=409, detail=f"Call is already {call.status}")

    now = datetime.now(timezone.utc)
    call.status = "active"
    call.answered_at = now
    db.commit()

    # Notify both parties via signaling WS
    asyncio.ensure_future(call_sig.broadcast(payload.call_id, {
        "type": "answered",
        "call_id": payload.call_id,
        "answered_at": now.isoformat(),
    }))

    return {"status": "active"}


@app.post("/call/reject")
async def call_reject(
    payload: CallActionRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    call = db.query(Call).filter(Call.id == payload.call_id).one_or_none()
    if not call:
        raise HTTPException(status_code=404, detail="Call not found")
    if call.callee_id != user.id and call.caller_id != user.id:
        raise HTTPException(status_code=403, detail="Not a participant")
    if call.status not in ("ringing",):
        raise HTTPException(status_code=409, detail=f"Call is already {call.status}")

    call.status = "rejected"
    call.ended_at = datetime.now(timezone.utc)
    db.commit()

    asyncio.ensure_future(call_sig.broadcast(payload.call_id, {
        "type": "rejected",
        "call_id": payload.call_id,
    }))

    return {"status": "rejected"}


@app.post("/call/end")
async def call_end(
    payload: CallActionRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    call = db.query(Call).filter(Call.id == payload.call_id).one_or_none()
    if not call:
        raise HTTPException(status_code=404, detail="Call not found")
    if call.callee_id != user.id and call.caller_id != user.id:
        raise HTTPException(status_code=403, detail="Not a participant")

    now = datetime.now(timezone.utc)
    if call.status not in ("ended", "rejected", "missed"):
        call.status = "ended"
        call.ended_at = now
        db.commit()

    asyncio.ensure_future(call_sig.broadcast(payload.call_id, {
        "type": "ended",
        "call_id": payload.call_id,
        "ended_at": now.isoformat(),
    }))

    return {"status": "ended"}


# ── Call signaling WebSocket ──────────────────────────────────────────────────

@app.websocket("/call/ws/{call_id}")
async def call_signaling_ws(
    websocket: WebSocket,
    call_id: str,
    token: str = Query(...),
    device_id: str = Query(...),
):
    """Bidirectional call signaling socket.

    Both caller and callee connect here after the call is initiated.
    The server relays JSON control frames between the two parties:
      {"type": "answered"} {"type": "rejected"} {"type": "ended"}
      {"type": "hold"}     {"type": "unhold"}   {"type": "pong"}
    """
    db: Session = SessionLocal()
    user = None
    try:
        user = ws_authenticate(token, device_id, db)
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        call = db.query(Call).filter(Call.id == call_id).one_or_none()
        if not call or (user.id != call.caller_id and user.id != call.callee_id):
            await websocket.close(code=4004, reason="Call not found or not a participant")
            return

        await call_sig.connect(call_id, user.id, websocket)

        while True:
            try:
                raw = await websocket.receive_text()
                msg = json.loads(raw)
                t = msg.get("type", "")
                if t == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif t in ("hold", "unhold", "ended", "rejected"):
                    # Relay to the other party
                    await call_sig.broadcast(call_id, msg, exclude_user_id=user.id)
                    # If ended/rejected, update DB
                    if t in ("ended", "rejected") and call.status not in ("ended", "rejected", "missed"):
                        call.status = t
                        call.ended_at = datetime.now(timezone.utc)
                        db.commit()
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        if user:
            call_sig.disconnect(call_id, user.id)
        db.close()


# ── Call audio relay WebSocket ────────────────────────────────────────────────

@app.websocket("/call/audio/ws/{call_id}")
async def call_audio_ws(
    websocket: WebSocket,
    call_id: str,
    token: str = Query(...),
    device_id: str = Query(...),
):
    """Binary audio relay socket.

    Each binary frame is forwarded verbatim to the other party.
    Frame format (enforced client-side):
      [8 bytes seq u64 LE] [12 bytes AES-GCM nonce] [ciphertext+tag bytes]

    The server never inspects the encrypted audio payload.
    """
    db: Session = SessionLocal()
    user = None
    try:
        user = ws_authenticate(token, device_id, db)
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        call = db.query(Call).filter(Call.id == call_id).one_or_none()
        if not call or (user.id != call.caller_id and user.id != call.callee_id):
            await websocket.close(code=4004, reason="Call not found or not a participant")
            return
        if call.status not in ("active", "ringing"):
            await websocket.close(code=4003, reason="Call not active")
            return

        await websocket.accept()
        call_audio.calls.setdefault(call_id, {})[user.id] = websocket

        while True:
            try:
                raw = await websocket.receive_bytes()
                await call_audio.relay(call_id, user.id, raw)
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        if user:
            call_audio.disconnect(call_id if call_id else "", user.id)
        db.close()
