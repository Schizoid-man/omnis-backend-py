# SQLite Database Schema — Private Chat API

This schema is derived directly from the REST API specification.
All timestamps are stored as UNIX epoch seconds.
Foreign keys must be enabled.

```sql
PRAGMA foreign_keys = ON;
```

---

## Design Decisions

- `device_id` uses **UUID v4** (TEXT, canonical string form)
- `calls.id` uses **UUID v4** (TEXT, canonical string form)
- Users are global
- Devices are per-user
- Sessions are per-user per-device
- Chats are **1-to-1 only**
- Messages are append-only
- Calls are **1-to-1 only** (caller ↔ callee)
- Strong foreign-key integrity
- No premature abstractions

---

## users

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
```
---

## sessions

Active login sessions bound to a device.

```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL, -- UUID v4
    session_token TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    created_at INTEGER NOT NULL,
    last_accessed INTEGER,
    expires_at INTEGER,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## chats

Private chat between exactly two users.

Invariant:
Always store the smaller user id as `user_a_id`.

```sql
CREATE TABLE chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a_id INTEGER NOT NULL,
    user_b_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,

    UNIQUE(user_a_id, user_b_id),
    FOREIGN KEY (user_a_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_b_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## messages

Chat messages.

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,

    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## calls

VoIP call records. Each row represents one call attempt from initiation through
termination. `status` follows a simple state machine:
`ringing → active → ended` or `ringing → rejected`.

```sql
CREATE TABLE calls (
    id TEXT PRIMARY KEY,              -- UUID v4
    caller_id INTEGER NOT NULL,
    callee_id INTEGER NOT NULL,
    chat_id INTEGER,                  -- nullable: links call to a chat thread
    status TEXT NOT NULL DEFAULT 'ringing',
                                      -- ringing | active | ended | rejected
    initiated_at INTEGER NOT NULL,
    answered_at INTEGER,              -- set when status → active
    ended_at INTEGER,                 -- set when status → ended | rejected

    FOREIGN KEY (caller_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (callee_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id)   REFERENCES chats(id) ON DELETE SET NULL
);
```

---

## Indexes (Required)

```sql
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_messages_chat_time ON messages(chat_id, created_at);
CREATE INDEX idx_chats_user_a ON chats(user_a_id);
CREATE INDEX idx_chats_user_b ON chats(user_b_id);
CREATE INDEX idx_calls_caller ON calls(caller_id);
CREATE INDEX idx_calls_callee ON calls(callee_id);
CREATE INDEX idx_calls_status ON calls(status);
```

---

## API Mapping Summary

- `/auth/register` → `devices`
- `/auth/signup` → `users`
- `/auth/login` → `sessions`
- `/auth/logout` → delete from `sessions`
- `/chats` → query `chats`
- `/chats/{chat_id}` → query `messages`
- `/chats/{chat_id}/messages` → insert into `messages`
- `/call/initiate` → insert into `calls` (status=ringing)
- `/call/answer` → update `calls` set status=active, answered_at
- `/call/reject` → update `calls` set status=rejected, ended_at
- `/call/end` → update `calls` set status=ended, ended_at
- `/call/ws/{call_id}`, `/call/audio/ws/{call_id}` → read `calls` for auth check

---

## Notes for Production

- Validate UUID v4 format at the API layer
- Consider rotating session tokens
- Add rate limiting if exposed publicly
- Migrate to WAL mode for concurrency

This schema is intentionally boring. That is a feature.
