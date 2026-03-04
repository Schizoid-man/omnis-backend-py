# Omnis Backend

## Overview

Omnis Backend is a [FastAPI](https://fastapi.tiangolo.com/) server for the Omnis end-to-end encrypted chat platform. It acts as a **zero-knowledge relay**: all message bodies and media blobs are treated as opaque encrypted content — the server never holds any key material that would allow it to read messages or files.

Clients available:
- **Web app** — [`static/index.html`](static/index.html) served at `/app`
- **TUI (terminal)** — [`../omnis-tui`](../omnis-tui/README.md)

For the complete REST + WebSocket contract see [endpoints.md](endpoints.md).  
For the client-side cryptography protocol see [frontend.md](frontend.md).

---

## What the Server Does

| Responsibility | Detail |
|---|---|
| **Authentication** | Argon2id password hashing; per-device session tokens (HMAC-SHA-256 of `SERVER_KEY`); token expiry |
| **Identity key distribution** | Stores each user's encrypted private key blob and public identity key; exposes public keys for peer lookup |
| **Chat management** | Creates one-to-one chats; enforces membership; returns chat list with last-message preview |
| **Epoch key relay** | Stores two copies of each wrapped epoch key (one per participant), returns the correct copy to the requesting user |
| **Message delivery** | Stores encrypted ciphertexts + nonces; pushes new messages to all connected WebSocket clients in real time via `ConnectionManager` |
| **Media upload/download** | Chunked upload (`init → chunks → finalize`), encrypted blob storage on disk; served back for decryption client-side |
| **Ephemeral messages** | Accepts `expires_at` timestamps; background task `_expire_messages()` prunes expired rows and broadcasts `message_deleted` events |
| **Session management** | Lists, revokes individual, and revokes all-other sessions |
| **Encrypted VoIP relay** | Server-relayed audio call infrastructure: REST endpoints for call signaling (initiate / answer / reject / end) + three WebSocket endpoints (presence push, call signaling, binary audio relay); the server forwards encrypted audio frames without decrypting them |

The server **never decrypts** any message body, media blob, or identity private key.

---

## Tech Stack

| Component | Library |
|---|---|
| Web framework | [FastAPI](https://fastapi.tiangolo.com/) |
| ORM | [SQLAlchemy 2.x](https://www.sqlalchemy.org/) (future mode) |
| Database | SQLite (`chat.db` in working directory) |
| Password hashing | [Argon2-CFFI](https://argon2-cffi.readthedocs.io/) |
| ASGI server | [Uvicorn](https://www.uvicorn.org/) |
| Media storage | Local filesystem (`./media/` directory) |

---

## Project Structure

```
Omnis-Backend/
├── main.py          Application entrypoint; all route handlers and WebSocket logic
├── models.py        SQLAlchemy ORM models (User, Session, Chat, ChatEpoch, Message,
│                    UserKey, MediaAttachment, PendingUpload, Call)
├── schema.py        Pydantic request/response schemas (incl. call schemas)
├── database.md      Database schema reference
├── endpoints.md     Complete REST + WebSocket API specification
├── frontend.md      Client cryptography contract and protocol notes
├── requirements.txt Python dependencies
└── static/
    ├── index.html   Web client
    ├── app.js       Web client JavaScript (E2E crypto, UI, WebSocket)
    └── style.css    Web client styles
```

---

## Database Schema

All data is stored in `chat.db` (SQLite). Foreign keys are enforced via `PRAGMA foreign_keys=ON`.

| Table | Purpose | Key columns |
|---|---|---|
| `users` | User accounts | `id`, `username`, `password_hash`, `created_at` |
| `user_keys` | Identity key material | `user_id`, `identity_pub`, `encrypted_identity_priv`, `kdf_salt`, `aead_nonce` |
| `sessions` | Per-device auth sessions | `id`, `user_id`, `device_id`, `session_token_hash`, `expires_at`, `last_accessed` |
| `chats` | One-to-one chat records | `id`, `user_a_id`, `user_b_id`, `created_at` |
| `chat_epochs` | Key epochs per chat | `id`, `chat_id`, `epoch_index`, `wrapped_key_a`, `wrapped_key_b`, `created_at` |
| `messages` | Encrypted messages | `id`, `chat_id`, `sender_id`, `epoch_id`, `reply_id`, `media_id`, `ciphertext`, `nonce`, `created_at`, `expires_at` |
| `media_attachments` | Finalised media blobs | `id`, `chat_id`, `uploader_id`, `file_type`, `filename`, `file_size`, `created_at` |
| `pending_uploads` | In-progress chunked uploads | `upload_id`, `chat_id`, `uploader_id`, `total_chunks`, `chunk_size`, `total_size`, `file_type`, `created_at` |
| `calls` | VoIP call records | `id` (UUID), `caller_id`, `callee_id`, `chat_id` (nullable), `status` (ringing/active/ended/rejected), `initiated_at`, `answered_at`, `ended_at` |

For full column definitions see [database.md](database.md).

---

## API Summary

Full specification: [endpoints.md](endpoints.md)

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/signup` | Register new user + publish identity key material |
| `POST` | `/auth/login` | Authenticate, create session, return token |
| `POST` | `/auth/logout` | Revoke current session |
| `GET` | `/auth/me` | Current user info |
| `GET` | `/auth/keyblob` | Retrieve encrypted private key blob |

### Users & Sessions

| Method | Path | Description |
|---|---|---|
| `GET` | `/users/sessions` | List all sessions for current user |
| `DELETE` | `/users/sessions/revoke/{id}` | Revoke a specific session |
| `DELETE` | `/users/sessions/revoke_other` | Revoke all sessions except current |
| `POST` | `/user/pkey/publish` | Publish identity public key |
| `GET` | `/user/pkey/get?username=` | Look up any user's public key |

### Chats & Messages

| Method | Path | Description |
|---|---|---|
| `GET` | `/chat/list` | List chats for current user |
| `POST` | `/chat/create` | Create (or return existing) one-to-one chat |
| `WS` | `/chat/ws/{chat_id}` | Real-time message delivery (history + push) |
| `GET` | `/chat/fetch/{chat_id}` | Paginated message history |
| `POST` | `/chat/{chat_id}/message` | Send an encrypted message |
| `GET` | `/chat/{chat_id}/{epoch_id}/fetch` | Fetch wrapped epoch key |
| `POST` | `/chat/{chat_id}/epoch` | Create new key epoch |

### Media

| Method | Path | Description |
|---|---|---|
| `POST` | `/media/upload/init` | Start a chunked upload session |
| `PUT` | `/media/upload/{id}/chunk/{i}` | Upload one chunk (raw bytes) |
| `POST` | `/media/upload/{id}/finalize` | Assemble chunks, persist blob, return `media_id` |
| `GET` | `/media/{media_id}` | Download encrypted media blob |

### VoIP Calls

| Method | Path | Description |
|---|---|---|
| `POST` | `/call/initiate` | Initiate an outgoing call; server creates a `Call` record and delivers a `call_invite` frame to the callee's presence WS |
| `POST` | `/call/answer` | Mark a call as active; broadcasts `answered` to both parties via the signaling WS |
| `POST` | `/call/reject` | Reject an incoming call; broadcasts `rejected` |
| `POST` | `/call/end` | Terminate an active call; broadcasts `ended` |
| `WS` | `/user/ws` | Per-user **presence** socket (receives `call_invite` pushes and pings) |
| `WS` | `/call/ws/{call_id}` | Per-call **signaling** socket (hold/unhold/answered/rejected/ended frames) |
| `WS` | `/call/audio/ws/{call_id}` | Per-call **binary audio relay** (forwards encrypted audio frames between callers without inspection) |

### In-memory managers (`main.py`)

| Class | Purpose |
|---|---|
| `PresenceManager` | Maps `user_id → WebSocket`; delivers `call_invite` JSON frames |
| `CallSignalingManager` | Maps `call_id → {user_id → WebSocket}`; broadcasts signaling frames |
| `CallAudioManager` | Maps `call_id → {user_id → WebSocket}`; relays raw binary audio from one party to the other |

### WebSocket Frames

**Server → Client** (presence WS)

| Frame type | Sent when |
|---|---|
| `call_invite` | A remote user calls this user via `POST /call/initiate` |
| `pong` | In response to a client `ping` |

**Server → Client** (chat WS)

| Frame type | Sent when |
|---|---|
| `history` | Immediately on connection (last 50 messages) |
| `new_message` | Any participant sends a message |
| `message_deleted` | A message's `expires_at` passes (ephemeral expiry) |
| `pong` | In response to a client `ping` |

**Client → Server**

| Frame type | Description |
|---|---|
| `ping` | Keepalive; server replies with `pong` |

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `SERVER_KEY` | **Yes** | Secret used for HMAC-SHA-256 session token hashing. Set to a long random string in production. |

Example:
```bash
export SERVER_KEY="$(openssl rand -hex 32)"
```

Media upload limits (hardcoded in `main.py`):

| Constant | Value |
|---|---|
| `MAX_CHUNK_SIZE` | 5 MiB per chunk |
| `MAX_TOTAL_SIZE` | 200 MiB per file |

---

## Running

### Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set required environment variable
export SERVER_KEY="dev-secret-change-in-production"

# Start server with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The web client is served at `http://localhost:8000/app`.

### Production (Docker)

```bash
# Build image
docker build -t omnis-backend .

# Run container
docker run -d \
  -p 8000:8000 \
  -e SERVER_KEY="your-production-secret" \
  -v omnis-data:/app/media \
  omnis-backend
```

See [`docker-compose.yml`](../docker-compose.yml) and [`dockerfile`](../dockerfile) for the full compose setup.

---

## Background Tasks

| Task | Interval | Purpose |
|---|---|---|
| `_expire_messages()` | Every 30 seconds | Deletes messages whose `expires_at` has passed; broadcasts `message_deleted` to all connected clients in the affected chat |
| `_purge_expired_uploads()` | Every 1 hour | Removes incomplete upload sessions older than 24 hours and their partial chunk files |

---

## Security Notes

- Session tokens are **HMAC-SHA-256** hashes of a random value, stored hashed in the database. The `SERVER_KEY` must be kept secret.
- Passwords are hashed with **Argon2id** at signup; plaintext passwords are never stored.
- The server applies **no rate limiting** by default — add a reverse proxy (nginx, Caddy) with rate limiting in production.
- CORS is currently open (`allow_origins=["*"]`). Restrict to your domain in production.
- Media blobs are stored **encrypted** on disk; the server cannot decrypt them without the per-file key, which only exists inside the epoch-encrypted message ciphertext.

---

## References

- [endpoints.md](endpoints.md) — Complete REST + WebSocket API specification
- [frontend.md](frontend.md) — Client cryptography protocol (key agreement, epoch rotation, media envelope format)
- [database.md](database.md) — Full database schema
