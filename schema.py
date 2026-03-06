from pydantic import BaseModel
from typing import Optional

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
    media_ids: Optional[list[int]] = None

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