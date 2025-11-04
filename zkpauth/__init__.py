"""Zero-knowledge authentication demo package."""

from .auth import authenticate, register_user
from .crypto import (
    SchnorrCommitment,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    derive_public_key,
    generate_secret,
)
from .richens import (
    RichensCapsule,
    RichensProof,
    issue_challenge,
    mint_capsule,
    respond_to_challenge,
    verify_attestation,
)
from .store import UserRecord, UserStore

__all__ = [
    "authenticate",
    "register_user",
    "SchnorrCommitment",
    "SchnorrProof",
    "SchnorrProver",
    "SchnorrVerifier",
    "derive_public_key",
    "generate_secret",
    "RichensCapsule",
    "RichensProof",
    "issue_challenge",
    "mint_capsule",
    "respond_to_challenge",
    "verify_attestation",
    "UserRecord",
    "UserStore",
]
