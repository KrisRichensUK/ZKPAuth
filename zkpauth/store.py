"""JSON-backed credential store for the zero-knowledge demo."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .crypto import derive_public_key, generate_secret


def _calculate_credential_id(public_key: int) -> str:
    """Derive a stable credential identifier from the public key."""

    byte_length = max(1, (public_key.bit_length() + 7) // 8)
    digest = hashlib.sha256(public_key.to_bytes(byte_length, "big")).hexdigest()
    return digest


@dataclass
class UserRecord:
    """Stored credential metadata."""

    credential_id: str
    public_key: int
    alias: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        payload: Dict[str, str] = {
            "credential_id": self.credential_id,
            "public_key": hex(self.public_key),
        }
        if self.alias is not None:
            payload["alias"] = self.alias
        return payload

    @staticmethod
    def from_dict(data: Dict[str, str]) -> "UserRecord":
        credential_id = data.get("credential_id")
        public_key = int(data["public_key"], 16)
        alias = data.get("alias") or data.get("username")

        if credential_id is None:
            credential_id = _calculate_credential_id(public_key)

        return UserRecord(
            credential_id=credential_id,
            public_key=public_key,
            alias=alias,
        )


class UserStore:
    """Persist credentials and optional human-readable aliases."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._ensure_file()

    def _ensure_file(self) -> None:
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as handle:
                json.dump({"users": []}, handle, indent=2)

    def _load(self) -> Dict[str, list]:
        with open(self.path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _save(self, payload: Dict[str, list]) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def get_by_alias(self, alias: str) -> Optional[UserRecord]:
        payload = self._load()
        for raw_user in payload.get("users", []):
            candidate_alias = raw_user.get("alias") or raw_user.get("username")
            if candidate_alias == alias:
                return UserRecord.from_dict(raw_user)
        return None

    def get_by_credential(self, credential_id: str) -> Optional[UserRecord]:
        payload = self._load()
        for raw_user in payload.get("users", []):
            stored_id = raw_user.get("credential_id")
            if stored_id is None and "public_key" in raw_user:
                stored_id = _calculate_credential_id(int(raw_user["public_key"], 16))
            if stored_id == credential_id:
                return UserRecord.from_dict(raw_user)
        return None

    def add_user(self, username: Optional[str] = None, secret: Optional[int] = None) -> Tuple[UserRecord, int]:
        payload = self._load()

        if username is not None:
            if any(
                (raw_user.get("alias") or raw_user.get("username")) == username
                for raw_user in payload.get("users", [])
            ):
                raise ValueError(f"Alias '{username}' already exists")

        secret_value = secret or generate_secret()
        public_key = derive_public_key(secret_value)
        credential_id = _calculate_credential_id(public_key)

        if any(raw_user.get("credential_id") == credential_id for raw_user in payload.get("users", [])):
            raise ValueError("Credential already registered")

        record = UserRecord(credential_id=credential_id, public_key=public_key, alias=username)

        payload.setdefault("users", []).append(record.to_dict())
        self._save(payload)
        return record, secret_value


__all__ = ["UserRecord", "UserStore"]
