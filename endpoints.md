# Omnis Chat API — REST Specification

## Base URL
```
http://localhost:8000
```

All requests and responses use JSON.  
All timestamps are UTC ISO-8601.

---

## Authentication Model

Authentication is **session-based**, scoped to a `(token, device_id)` pair.

### Headers (required on authenticated endpoints)

```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

- `Authorization` contains the session token returned by `POST /auth/login`.
- `X-Device-ID` is a client-generated UUID v4 that identifies the device / browser instance.

Unless explicitly stated otherwise, all endpoints that depend on authentication
require both headers.

---

## Cryptographic Model (High-Level)

- Each user has a long-term **identity keypair**.
- The **public key** is stored on the server.
- The **private key** is encrypted client-side with a passphrase and stored as an
  opaque blob on the server (the server never sees the passphrase).
- Message bodies are treated as opaque payloads; any end-to-end encryption is
  implemented on the client side.

The API exposes endpoints to upload and retrieve identity key material; it does
not provide server-side encryption or decryption of messages.

---

## Health

### GET /

Simple health check.

**Auth:** none

**Response**
```json
{
  "PING": "PONG"
}
```

---

## Auth Endpoints

### POST /auth/signup

Creates a new user and stores initial identity key material.

**Auth:** none

**Request body**
```json
{
  "username": "string",
  "password": "string",
  "identity_pub": "string",
  "encrypted_identity_priv": "string",
  "kdf_salt": "string",
  "aead_nonce": "string"
}
```

**Response — 201 Created**
```json
{
  "id": 1,
  "username": "alice"
}
```

Errors:
- `400` — username already exists

---

### POST /auth/login

Authenticates a user and creates a new session for the device.

**Headers**
```
X-Device-ID: <uuid-v4>
User-Agent: <string> (optional)
```

**Request body**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response — 200 OK**
```json
{
  "token": "string"
}
```

Errors:
- `401` — invalid username or password

---

### POST /auth/logout

Logs out the **current session only**.

**Headers**
```
Authorization: Bearer <token>
```

**Response — 200 OK**
```json
{
  "status": "logged out"
}
```

Errors:
- `401` — invalid or unknown token

---

### GET /auth/me

Returns the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
{
  "id": 1,
  "username": "string"
}
```

Errors:
- `401` — unauthorized

---

### GET /auth/keyblob

Returns the encrypted identity key material for the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
{
  "identity_pub": "string",
  "encrypted_identity_priv": "string",
  "kdf_salt": "string",
  "aead_nonce": "string"
}
```

Errors:
- `401` — unauthorized
- `404` — identity key material not found

---

## Account & Session Management

### GET /users/sessions

Lists all active sessions for the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
[
  {
    "id": 12,
    "device_id": "uuid-v4",
    "user_agent": "string or null",
    "last_accessed": "ISO-8601",
    "created_at": "ISO-8601",
    "expires_at": "ISO-8601 or null",
    "current": true
  }
]
```

The `current` field is `true` only for the session corresponding to the
combination of the provided `Authorization` token and `X-Device-ID`.

Errors:
- `401` — unauthorized

---

### DELETE /users/sessions/revoke/{session_id}

Revokes a specific session belonging to the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `session_id` — integer

**Response — 200 OK**
```json
{
  "status": "revoked"
}
```

Errors:
- `401` — unauthorized
- `404` — session not found or does not belong to user

---

### DELETE /users/sessions/revoke_other

Revokes all sessions for the authenticated user **except** the current one.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
{
  "status": "other sessions revoked"
}
```

Errors:
- `401` — unauthorized

---

## User Public Key Endpoints

### POST /user/pkey/publish

Publishes identity key material for the authenticated user. Fails if a key
already exists.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Request body**
```json
{
  "identity_pub": "string",
  "encrypted_identity_priv": "string",
  "kdf_salt": "string",
  "aead_nonce": "string"
}
```

**Response — 201 Created**
```json
{
  "status": "published"
}
```

Errors:
- `401` — unauthorized
- `409` — public key already published

---

### GET /user/pkey/get

Fetches the public identity key for a given username.

**Auth:** none (public lookup)

**Query parameters**
```
username: string (required)
```

**Response — 200 OK**
```json
{
  "username": "string",
  "identity_pub": "string"
}
```

Errors:
- `404` — user not found
- `404` — user has not published a public key

---

## Chat Endpoints

### GET /chat/list

Lists chats for the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
[
  {
    "chat_id": 42,
    "with_user": "other_username"
  }
]
```

Errors:
- `401` — unauthorized

---

### POST /chat/create

Creates a one-to-one chat with another user, identified by username.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Request body**
```json
{
  "username": "target_username"
}
```

**Response — 200 OK**
```json
{
  "chat_id": 42
}
```

If a chat between the two users already exists, the existing `chat_id` is
returned.

Errors:
- `401` — unauthorized
- `404` — target user not found

---

### WebSocket /chat/ws/{chat_id}

Opens a persistent WebSocket connection for real-time message delivery in a
chat. Replaces polling of `GET /chat/fetch/{chat_id}` for the active chat
window.

**Connection URL**
```
ws://<host>:8000/chat/ws/{chat_id}?token=<session_token>&device_id=<uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Query parameters** (used for authentication)
```
token: string (required)   # the session token from POST /auth/login
device_id: string (required)  # UUID v4 device identifier
```

**Connection lifecycle**

1. The server authenticates the token + device_id pair.
   - On failure the connection is closed with code `4001` ("Unauthorized").
   - If the user is not a member of the chat, closed with `4004` ("Chat not found").
2. Immediately after connecting, the server sends a `history` frame containing
   the last 50 messages (same shape as the old REST response).
3. Whenever a new message is sent via `POST /chat/{chat_id}/message`, the
   server pushes a `new_message` frame to every connected member.
4. The client may send `{"type":"ping"}` at any time; the server replies with
   `{"type":"pong"}`.
5. Either side may close the connection normally.

**Server → Client frames**

*history* (sent once on connect)
```json
{
  "type": "history",
  "messages": [
    {
      "id": 1001,
      "sender_id": 1,
      "epoch_id": 5,
      "reply_id": 1000,
      "ciphertext": "base64-or-opaque-string",
      "nonce": "string",
      "created_at": "ISO-8601"
    }
  ],
  "next_cursor": 1001
}
```

*new_message* (pushed on each new message)
```json
{
  "type": "new_message",
  "message": {
    "id": 1002,
    "sender_id": 2,
    "epoch_id": 5,
    "reply_id": null,
    "ciphertext": "base64-or-opaque-string",
    "nonce": "string",
    "created_at": "ISO-8601"
  }
}
```

*pong*
```json
{
  "type": "pong"
}
```

**Client → Server frames**

*ping*
```json
{
  "type": "ping"
}
```

**Close codes**
| Code | Meaning |
|------|---------|
| 4001 | Unauthorized (bad token / device_id) |
| 4004 | Chat not found or user is not a member |

---

### GET /chat/fetch/{chat_id}

Fetches messages for a chat, in chronological order (oldest to newest).
Primarily used for **scrollback / pagination**; for real-time delivery prefer
the `WebSocket /chat/ws/{chat_id}` endpoint above.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Query parameters**
```
before_id: integer (optional)  # fetch messages with id < before_id
limit: integer (optional, default 50, max 100)
```

**Response — 200 OK**
```json
{
  "messages": [
    {
      "id": 1001,
      "sender_id": 1,
      "epoch_id": 5,
      "reply_id": 1000,
      "ciphertext": "base64-or-opaque-string",
      "nonce": "string",
      "created_at": "ISO-8601"
    }
  ],
  "next_cursor": 1001
}
```

- `next_cursor` is the id of the oldest message in the returned batch, or
  `null` if there are no messages. To page backwards in time, pass this value
  as `before_id` in the next request.
- Each message contains an `epoch_id` field. Use `GET /chat/{chat_id}/{epoch_id}/fetch`
  to retrieve the wrapped epoch key needed for decryption.

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member

---

### GET /chat/{chat_id}/{epoch_id}/fetch

Fetches the wrapped epoch key for a specific epoch in a chat.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer
- `epoch_id` — integer

**Response — 200 OK**
```json
{
  "epoch_id": 5,
  "epoch_index": 1,
  "wrapped_key": "base64-or-opaque-string"
}
```

- `wrapped_key` is the epoch key wrapped for the authenticated user.

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member
- `404` — epoch not found

---

### POST /chat/{chat_id}/epoch

Creates a new key epoch for a chat. Epochs are used by clients to rotate
message encryption keys.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Request body**
```json
{
  "wrapped_key_a": "base64-or-opaque-string",
  "wrapped_key_b": "base64-or-opaque-string"
}
```

**Response — 201 Created**
```json
{
  "epoch_id": 5,
  "epoch_index": 1
}
```

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member
- `400` — epoch rotation not allowed yet (message-count gate not satisfied)
- `429` — epoch creation throttled (too frequent requests)

---

### POST /chat/{chat_id}/message

Sends a message in a chat.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Request body**
```json
{
  "epoch_id": 5,
  "ciphertext": "base64-or-opaque-string",
  "nonce": "string",
  "reply_id": 1000
}
```

**Response — 201 Created**
```json
{
  "id": 1001,
  "epoch_id": 5,
  "created_at": "ISO-8601"
}
```

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member
- `409` — unknown epoch
- `409` — stale epoch; a newer epoch exists and must be used
- `409` — epoch not initialized (wrapped keys missing)

---

## VoIP Call Endpoints

All call REST endpoints require authentication. Pass the token via
`Authorization: Bearer <token>` header (same auth scheme as other
authenticated endpoints).

---

### `POST /call/initiate`

Start an outgoing call to another user.

**Auth:** required

**Request body:**
```json
{
  "callee_username": "string",
  "chat_id": 1
}
```
`chat_id` is optional (`null` allowed) — links the call to an existing chat.

**Response `200`:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ringing",
  "caller_username": "alice",
  "callee_username": "bob"
}
```

**Side effects:**
- Creates a `calls` row with `status = ringing`.
- Pushes a `call_invite` frame to the callee's presence WebSocket:
  ```json
  {
    "type": "call_invite",
    "call_id": "550e8400-e29b-41d4-a716-446655440000",
    "caller_username": "alice",
    "initiated_at": "2025-01-01T12:00:00Z"
  }
  ```

**Errors:**
- `404` — callee not found
- `409` — callee already in an active call

---

### `POST /call/answer`

Accept an incoming call. Called by the callee after receiving a `call_invite`.

**Auth:** required

**Request body:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response `200`:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "active"
}
```

**Side effects:**
- Sets `calls.status = active` and records `answered_at`.
- Broadcasts `{"type": "answered"}` to all participants on `/call/ws/{call_id}`.

**Errors:**
- `403` — caller is not the callee of this call
- `404` — call not found
- `409` — call is not in `ringing` state

---

### `POST /call/reject`

Reject an incoming call.

**Auth:** required

**Request body:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response `200`:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "rejected"
}
```

**Side effects:**
- Sets `calls.status = rejected` and records `ended_at`.
- Broadcasts `{"type": "rejected"}` to all participants on `/call/ws/{call_id}`.

**Errors:**
- `403` — caller is not the callee of this call
- `404` — call not found
- `409` — call is not in `ringing` state

---

### `POST /call/end`

End an active (or ringing) call. May be called by either the caller or callee.

**Auth:** required

**Request body:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response `200`:**
```json
{
  "call_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ended"
}
```

**Side effects:**
- Sets `calls.status = ended` and records `ended_at`.
- Broadcasts `{"type": "ended"}` to all participants on `/call/ws/{call_id}`.

**Errors:**
- `403` — authenticated user is not a participant in this call
- `404` — call not found
- `409` — call is already ended or rejected

---

### `WS /user/ws`

Per-user **presence** WebSocket. Delivers incoming call invitations and
keepalive pings to the authenticated user.

**Query params:**
| Param | Required | Description |
|---|---|---|
| `token` | yes | Auth token |
| `device_id` | yes | Client device identifier |

**Server → Client frames (JSON):**

| `type` | Sent when | Extra fields |
|---|---|---|
| `call_invite` | Another user calls this user (`POST /call/initiate`) | `call_id`, `caller_username`, `initiated_at` |
| `pong` | Client sent `{"type": "ping"}` | — |

**Client → Server frames (JSON):**

| `type` | Description |
|---|---|
| `ping` | Keepalive; server replies with `pong` |

**Lifecycle:** Only one presence connection is tracked per user. A new
connection replaces any previous connection for that user.

---

### `WS /call/ws/{call_id}`

Per-call **signaling** WebSocket. Both the caller and callee connect here after
the call is initiated. Used for hold/unhold and terminal state notifications.

**Path params:**
| Param | Description |
|---|---|
| `call_id` | UUID of the call (from `POST /call/initiate`) |

**Query params:**
| Param | Required | Description |
|---|---|---|
| `token` | yes | Auth token |
| `device_id` | yes | Client device identifier |

**Server → Client frames (JSON):**

| `type` | Meaning |
|---|---|
| `answered` | Callee accepted the call |
| `rejected` | Callee rejected the call |
| `ended` | A participant ended the call |
| `hold` | The remote party has put the call on hold |
| `unhold` | The remote party has resumed the call |

**Client → Server frames (JSON):**

| `type` | Meaning |
|---|---|
| `hold` | Local party puts the call on hold |
| `unhold` | Local party resumes the call |
| `ping` | Keepalive |

**Errors:** WebSocket is closed with code `4001` if the token is invalid or
the user is not a participant in the specified call.

---

### `WS /call/audio/ws/{call_id}`

Per-call **binary audio relay** WebSocket. The server relays encrypted binary
audio frames from one participant to the other without inspection or
decryption.

**Path params:**
| Param | Description |
|---|---|
| `call_id` | UUID of the call |

**Query params:**
| Param | Required | Description |
|---|---|---|
| `token` | yes | Auth token |
| `device_id` | yes | Client device identifier |

**Frame format (binary, client → server → remote):**

```
┌───────────────┬──────────────────┬────────────────────────────┐
│  seq  (8 B)   │  nonce  (12 B)   │  AES-GCM ciphertext + tag  │
└───────────────┴──────────────────┴────────────────────────────┘
```

| Field | Size | Description |
|---|---|---|
| `seq` | 8 bytes, big-endian u64 | Monotonic sequence number; used by receiver to detect reordering |
| `nonce` | 12 bytes | Random AES-GCM nonce |
| `ciphertext + tag` | variable | AES-GCM encrypted audio (key derived via ECDH + HKDF) |

**Behaviour:**
- Any binary message received from participant A is forwarded verbatim to
  participant B (and vice-versa).
- The server never parses or decrypts audio content.
- JSON messages are ignored on this socket.

**Errors:** WebSocket is closed with code `4001` if the token is invalid or
the user is not a participant in the specified call.

---

## Notes & Non-Goals (Current State)

- The server does not perform any encryption or decryption of messages; it
  stores and returns message bodies as provided by clients.
- Identity private keys are stored only in encrypted form; the server does not
  see user passphrases.
- Key epochs and wrapped epoch keys are managed via the `/chat/{chat_id}/epoch`
  endpoint and retrieved individually via `/chat/{chat_id}/{epoch_id}/fetch`.
- Clients should cache epoch keys locally and only request epoch keys for
  epochs they have not yet decrypted.