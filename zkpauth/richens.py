"""Implementation of the experimental Richens attestation method."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple

from .constants import G, P, Q


def _int_to_bytes(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def _derive_coefficients(essence: bytes, context: str) -> Tuple[int, int, int]:
    material = essence + context.encode("utf-8")
    stream = hashlib.shake_256(material).digest(96)
    a = int.from_bytes(stream[0:32], "big") % Q
    b = int.from_bytes(stream[32:64], "big") % Q
    c = int.from_bytes(stream[64:96], "big") % Q
    return a, b, c


def _compute_fingerprint(vector: Tuple[int, int, int], context: str) -> str:
    hasher = hashlib.blake2b(digest_size=32)
    for value in vector:
        hasher.update(_int_to_bytes(value))
    hasher.update(context.encode("utf-8"))
    return hasher.hexdigest()


@dataclass
class RichensCapsule:
    """Stateless identity capsule transmitted by the participant."""

    vector: Tuple[int, int, int]
    context: str
    anchor: int
    fingerprint: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "vector": [hex(component) for component in self.vector],
            "context": self.context,
            "anchor": hex(self.anchor),
            "fingerprint": self.fingerprint,
        }

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "RichensCapsule":
        vector_hex = data["vector"]
        context = data["context"]
        anchor_hex = data["anchor"]
        fingerprint = data["fingerprint"]
        vector = tuple(int(value, 16) for value in vector_hex)  # type: ignore[arg-type]
        anchor = int(anchor_hex, 16)
        capsule = RichensCapsule(vector=vector, context=context, anchor=anchor, fingerprint=fingerprint)
        if capsule.anchor != _derive_anchor(capsule.vector):
            raise ValueError("Capsule anchor mismatch")
        if capsule.fingerprint != _compute_fingerprint(capsule.vector, capsule.context):
            raise ValueError("Capsule fingerprint mismatch")
        return capsule

    @property
    def persona(self) -> str:
        return self.fingerprint[:24]


def _derive_anchor(vector: Tuple[int, int, int]) -> int:
    # Deterministically combine the commitments into a stability anchor.
    return (
        pow(vector[0], 2, P)
        * pow(vector[1], 3, P)
        * pow(vector[2], 5, P)
    ) % P


@dataclass
class RichensProof:
    """Proof that a participant controls the Richens essence."""

    response: int
    orbital: int
    parity: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "response": hex(self.response),
            "orbital": hex(self.orbital),
            "parity": self.parity,
        }

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "RichensProof":
        return RichensProof(
            response=int(data["response"], 16),
            orbital=int(data["orbital"], 16),
            parity=str(data["parity"]),
        )


def mint_capsule(essence: bytes, *, context: str = "richens-global") -> RichensCapsule:
    coefficients = _derive_coefficients(essence, context)
    vector = tuple(pow(G, value, P) for value in coefficients)
    anchor = _derive_anchor(vector)
    fingerprint = _compute_fingerprint(vector, context)
    return RichensCapsule(vector=vector, context=context, anchor=anchor, fingerprint=fingerprint)


def issue_challenge(*, bits: int = 192) -> int:
    size = min(bits, Q.bit_length())
    while True:
        candidate = secrets.randbits(size)
        if 0 < candidate < Q:
            return candidate


def respond_to_challenge(essence: bytes, challenge: int, *, context: str) -> RichensProof:
    a, b, c = _derive_coefficients(essence, context)
    challenge_mod = challenge % Q
    polynomial = (a + b * challenge_mod + c * pow(challenge_mod, 2, Q)) % Q
    orbital = pow(G, polynomial, P)
    parity = hashlib.blake2b(
        _int_to_bytes(challenge_mod) + _int_to_bytes(orbital) + context.encode("utf-8"),
        digest_size=32,
    ).hexdigest()
    return RichensProof(response=polynomial, orbital=orbital, parity=parity)


def verify_attestation(capsule: RichensCapsule, challenge: int, proof: RichensProof) -> bool:
    if capsule.anchor != _derive_anchor(capsule.vector):
        return False
    if capsule.fingerprint != _compute_fingerprint(capsule.vector, capsule.context):
        return False

    challenge_mod = challenge % Q

    expected = pow(capsule.vector[0], 1, P)
    expected = (expected * pow(capsule.vector[1], challenge_mod, P)) % P
    expected = (expected * pow(capsule.vector[2], pow(challenge_mod, 2, Q), P)) % P

    if pow(G, proof.response, P) != proof.orbital:
        return False
    if proof.orbital != expected:
        return False

    expected_parity = hashlib.blake2b(
        _int_to_bytes(challenge_mod) + _int_to_bytes(proof.orbital) + capsule.context.encode("utf-8"),
        digest_size=32,
    ).hexdigest()
    return secrets.compare_digest(proof.parity, expected_parity)


__all__ = [
    "RichensCapsule",
    "RichensProof",
    "issue_challenge",
    "mint_capsule",
    "respond_to_challenge",
    "verify_attestation",
]
