"""High level registration and authentication helpers."""

from __future__ import annotations

from typing import Dict, List

from .constants import ROUNDS
from .crypto import SchnorrProof, run_single_round
from .store import UserRecord, UserStore


def register_user(
    store: UserStore,
    alias: str | None = None,
    secret: int | None = None,
) -> Dict[str, str | None]:
    record, secret_value = store.add_user(username=alias, secret=secret)
    return {
        "credential_id": record.credential_id,
        "alias": record.alias,
        "public_key": hex(record.public_key),
        "secret": hex(secret_value),
    }


def _resolve_record(store: UserStore, identifier: str, use_alias: bool) -> UserRecord | None:
    if use_alias:
        return store.get_by_alias(identifier)
    return store.get_by_credential(identifier)


def authenticate(
    store: UserStore,
    identifier: str,
    secret: int,
    *,
    use_alias: bool = True,
) -> Dict[str, object]:
    record = _resolve_record(store, identifier, use_alias)
    if record is None:
        raise ValueError("Unknown credential")

    transcripts: List[Dict[str, str]] = []
    success_rounds = 0
    for _ in range(ROUNDS):
        ok, proof, commitment = run_single_round(secret, record.public_key)
        transcripts.append(_serialize_round(proof, commitment))
        if ok:
            success_rounds += 1

    return {
        "credential_id": record.credential_id,
        "alias": record.alias,
        "rounds": transcripts,
        "success": success_rounds == ROUNDS,
    }


def _serialize_round(proof: SchnorrProof, commitment: int) -> Dict[str, str]:
    return {
        "commitment": hex(commitment),
        "challenge": hex(proof.challenge),
        "response": hex(proof.response),
    }


__all__ = ["authenticate", "register_user"]
