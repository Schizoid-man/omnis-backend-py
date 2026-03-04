from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Index,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.engine import Engine
import sqlite3

@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, _):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

DATABASE_URL = "sqlite:///chat.db"

engine = create_engine(
    DATABASE_URL,
    future=True,
    echo=False,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(128), nullable=False, unique=True)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class UserKey(Base):
    __tablename__ = "user_keys"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)

    identity_pub = Column(String(128), nullable=False)

    encrypted_identity_priv = Column(Text, nullable=False)
    kdf_salt = Column(String(64), nullable=False)
    aead_nonce = Column(String(48), nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(String(36), nullable=False)  # UUID v4
    session_token_hash = Column(String(128), nullable=False, unique=True)
    user_agent = Column(String(64), nullable=True)
    last_accessed = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=True)

    user = relationship("User")

class ChatEpoch(Base):
    __tablename__ = "chat_epochs"

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey("chats.id", ondelete="CASCADE"))
    epoch_index = Column(Integer, nullable=False)

    wrapped_key_a = Column(Text, nullable=False)
    wrapped_key_b = Column(Text, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("chat_id", "epoch_index"),)

class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True)
    user_a_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_b_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_a_id", "user_b_id"),
    )


class MediaAttachment(Base):
    """Stores metadata for an encrypted media blob uploaded by a participant."""
    __tablename__ = "media_attachments"

    id = Column(Integer, primary_key=True)
    uploader_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    chat_id = Column(
        Integer,
        ForeignKey("chats.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Absolute path to the assembled encrypted blob on disk
    storage_path = Column(String(512), nullable=False)
    total_size = Column(Integer, nullable=False)
    # Client-reported type hint: "image", "video", "audio", "document", "file"
    # The server never inspects this value; it is purely a hint for the UI.
    file_type = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class PendingUpload(Base):
    """Tracks an in-progress chunked upload session."""
    __tablename__ = "pending_uploads"

    id = Column(String(36), primary_key=True)  # UUID
    uploader_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    chat_id = Column(
        Integer,
        ForeignKey("chats.id", ondelete="CASCADE"),
        nullable=False,
    )
    total_size = Column(Integer, nullable=False)
    chunk_size = Column(Integer, nullable=False)
    total_chunks = Column(Integer, nullable=False)
    chunks_received = Column(Integer, default=0, nullable=False)
    storage_dir = Column(String(512), nullable=False)
    file_type = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class Call(Base):
    """Tracks VoIP calls between two users."""
    __tablename__ = "calls"

    id            = Column(String(36), primary_key=True)   # UUID
    caller_id     = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    callee_id     = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    # Optional: the chat the call was initiated from.
    chat_id       = Column(Integer, ForeignKey("chats.id", ondelete="SET NULL"), nullable=True)
    # ringing | active | ended | rejected | missed
    status        = Column(String(16), nullable=False, default="ringing")
    initiated_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    answered_at   = Column(DateTime, nullable=True)
    ended_at      = Column(DateTime, nullable=True)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    chat_id = Column(
        Integer,
        ForeignKey("chats.id", ondelete="CASCADE"),
        nullable=False,
    )
    sender_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    reply_id = Column(
        Integer,
        ForeignKey("messages.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Optional reference to an encrypted media attachment.
    # The ciphertext field carries a JSON envelope that contains the per-file
    # AES-256-GCM key — the server never sees plaintext or key material.
    media_id = Column(
        Integer,
        ForeignKey("media_attachments.id", ondelete="SET NULL"),
        nullable=True,
    )

    epoch_id = Column(Integer, ForeignKey("chat_epochs.id"))
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(48), nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # If set, the message (and linked media) are auto-deleted after this UTC timestamp.
    expires_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_messages_chat_created", "chat_id", "created_at"),
        Index("ix_messages_reply_id", "reply_id"),
        Index("ix_messages_media_id", "media_id"),
    )


def init_db():
    from sqlalchemy import text as sa_text
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        # Idempotent migrations
        for stmt in [
            "ALTER TABLE messages ADD COLUMN media_id INTEGER REFERENCES media_attachments(id) ON DELETE SET NULL",
            "ALTER TABLE messages ADD COLUMN expires_at DATETIME",
            # VoIP calls table (SQLite CREATE TABLE IF NOT EXISTS handles the case where
            # it already exists, so no try/except needed here — the ORM covers it above).
        ]:
            try:
                conn.execute(sa_text(stmt))
                conn.commit()
            except Exception:
                pass  # Column already exists
