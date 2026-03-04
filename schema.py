from pydantic import BaseModel, field_validator
from typing import Optional, Literal

class SignupRequest(BaseModel):
    username: str
    password: str

    identity_pub: str
    encrypted_identity_priv: str
    kdf_salt: str
    aead_nonce: str

class AuthRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    username: str

class EpochRequest(BaseModel):
    wrapped_key_a: str
    wrapped_key_b: str

class MessageRequest(BaseModel):
    epoch_id: int
    ciphertext: str
    nonce: str
    reply_id: Optional[int] = None
    # When set, links this message to an already-finalised MediaAttachment.
    # The file's per-file AES-GCM key is embedded inside the encrypted ciphertext
    # so the server never has access to the key or the plaintext file data.
    media_id: Optional[int] = None
    # ISO 8601 UTC string. When set the server deletes this message (and linked
    # media) after the given timestamp and notifies connected clients via WS.
    expires_at: Optional[str] = None

class LogoutRequest(BaseModel):
    session_id: int
    all: bool

class PublishRequest(BaseModel):
    identity_pub: str
    encrypted_identity_priv: str
    kdf_salt: str
    aead_nonce: str

class PKeyResponse(BaseModel):
    username: str
    identity_pub: str

# ── Media upload schemas ──────────────────────────────────────────────────────

_VALID_FILE_TYPES = {"image", "video", "audio", "document", "file"}

class MediaInitRequest(BaseModel):
    chat_id: int
    total_size: int       # bytes, encrypted blob size
    chunk_size: int       # bytes per chunk (max 5 MiB)
    total_chunks: int
    file_type: str        # one of _VALID_FILE_TYPES

    @field_validator("file_type")
    @classmethod
    def validate_file_type(cls, v: str) -> str:
        if v not in _VALID_FILE_TYPES:
            raise ValueError(f"file_type must be one of {_VALID_FILE_TYPES}")
        return v

    @field_validator("total_size")
    @classmethod
    def validate_total_size(cls, v: int) -> int:
        if v <= 0 or v > 200 * 1024 * 1024:
            raise ValueError("total_size must be between 1 byte and 200 MiB")
        return v

    @field_validator("chunk_size")
    @classmethod
    def validate_chunk_size(cls, v: int) -> int:
        if v <= 0 or v > 5 * 1024 * 1024:
            raise ValueError("chunk_size must be between 1 byte and 5 MiB")
        return v

    @field_validator("total_chunks")
    @classmethod
    def validate_total_chunks(cls, v: int) -> int:
        if v < 1:
            raise ValueError("total_chunks must be at least 1")
        return v


# ── VoIP call schemas ─────────────────────────────────────────────────────────

class CallInitiateRequest(BaseModel):
    callee_username: str
    chat_id: Optional[int] = None

class CallActionRequest(BaseModel):
    call_id: str

class CallInitiateResponse(BaseModel):
    call_id: str
    status: str
    caller_username: str
    callee_username: str
