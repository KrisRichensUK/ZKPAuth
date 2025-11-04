"""FastAPI-powered Schnorr authentication service."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .crypto import SchnorrProof, SchnorrVerifier
from .store import UserStore


@dataclass
class _SessionState:
    credential_id: str
    commitment: int
    challenge: int


class _SessionManager:
    def __init__(self) -> None:
        self._sessions: Dict[str, _SessionState] = {}

    def create(self, credential_id: str, commitment: int, challenge: int) -> str:
        session_id = secrets.token_urlsafe(16)
        self._sessions[session_id] = _SessionState(
            credential_id=credential_id,
            commitment=commitment,
            challenge=challenge,
        )
        return session_id

    def pop(self, session_id: str) -> _SessionState:
        state = self._sessions.pop(session_id, None)
        if state is None:
            raise KeyError(session_id)
        return state


class RegisterRequest(BaseModel):
    alias: str | None = None
    secret: str | None = None


class RegisterResponse(BaseModel):
    credential_id: str
    alias: str | None
    public_key: str
    secret: str


class LoginStartRequest(BaseModel):
    credential_id: str
    commitment: str


class LoginStartResponse(BaseModel):
    session: str
    challenge: str


class LoginFinishRequest(BaseModel):
    session: str
    response: str


class LoginFinishResponse(BaseModel):
    success: bool


app = FastAPI(title="ZKPAuth", description="Passwordless Schnorr authentication demo")
_store = UserStore("users.json")
_sessions = _SessionManager()


@app.post("/register", response_model=RegisterResponse)
async def register(request: RegisterRequest) -> RegisterResponse:
    if request.secret:
        try:
            secret_value = int(request.secret, 16)
        except ValueError as exc:  # pragma: no cover - input validation
            raise HTTPException(status_code=400, detail="Secret must be hex encoded") from exc
    else:
        secret_value = None
    record, secret_int = _store.add_user(username=request.alias, secret=secret_value)
    return RegisterResponse(
        credential_id=record.credential_id,
        alias=record.alias,
        public_key=hex(record.public_key),
        secret=hex(secret_int),
    )


@app.post("/login/start", response_model=LoginStartResponse)
async def login_start(request: LoginStartRequest) -> LoginStartResponse:
    record = _store.get_by_credential(request.credential_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown credential")

    try:
        commitment = int(request.commitment, 16)
    except ValueError as exc:  # pragma: no cover - input validation
        raise HTTPException(status_code=400, detail="Commitment must be hex encoded") from exc
    if commitment <= 0:
        raise HTTPException(status_code=400, detail="Invalid commitment")

    verifier = SchnorrVerifier(record.public_key)
    challenge = verifier.random_challenge()
    session = _sessions.create(record.credential_id, commitment, challenge)
    return LoginStartResponse(session=session, challenge=hex(challenge))


@app.post("/login/finish", response_model=LoginFinishResponse)
async def login_finish(request: LoginFinishRequest) -> LoginFinishResponse:
    try:
        state = _sessions.pop(request.session)
    except KeyError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Unknown session") from exc

    record = _store.get_by_credential(state.credential_id)
    if record is None:  # pragma: no cover - should not happen
        raise HTTPException(status_code=404, detail="Unknown credential")

    try:
        response_int = int(request.response, 16)
    except ValueError as exc:  # pragma: no cover - input validation
        raise HTTPException(status_code=400, detail="Response must be hex encoded") from exc

    proof = SchnorrProof(challenge=state.challenge, response=response_int)
    verifier = SchnorrVerifier(record.public_key)
    success = verifier.verify(state.commitment, proof)
    return LoginFinishResponse(success=success)


__all__ = ["app"]
