"""Core arithmetic helpers for the Schnorr identification protocol."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Tuple

from .constants import CHALLENGE_BITS, G, P, Q


@dataclass
class SchnorrCommitment:
    """Commitment value exchanged in the first round of the protocol."""

    commitment: int
    nonce: int


@dataclass
class SchnorrProof:
    """Proof resulting from an interaction between prover and verifier."""

    challenge: int
    response: int


class SchnorrProver:
    """Prover that holds the long-lived secret and crafts zero-knowledge proofs."""

    def __init__(self, secret: int) -> None:
        if not 0 < secret < Q:
            raise ValueError("Secret must lie in the multiplicative subgroup")
        self.secret = secret

    @staticmethod
    def random_nonce() -> int:
        return secrets.randbelow(Q - 1) + 1

    def commit(self) -> SchnorrCommitment:
        nonce = self.random_nonce()
        commitment = pow(G, nonce, P)
        return SchnorrCommitment(commitment=commitment, nonce=nonce)

    def prove(self, challenge: int, commitment: SchnorrCommitment) -> SchnorrProof:
        if not 0 <= challenge < 2**CHALLENGE_BITS:
            raise ValueError("Challenge outside of configured range")
        response = (commitment.nonce + challenge * self.secret) % Q
        return SchnorrProof(challenge=challenge, response=response)


class SchnorrVerifier:
    """Verifier that checks Schnorr proofs against a public key."""

    def __init__(self, public_key: int) -> None:
        if not 0 < public_key < P:
            raise ValueError("Invalid public key")
        self.public_key = public_key

    @staticmethod
    def random_challenge() -> int:
        return secrets.randbits(CHALLENGE_BITS)

    def verify(self, commitment_value: int, proof: SchnorrProof) -> bool:
        left = pow(G, proof.response, P)
        right = (commitment_value * pow(self.public_key, proof.challenge, P)) % P
        return left == right


def generate_secret() -> int:
    """Generate a fresh secret suitable for Schnorr identification."""

    return secrets.randbelow(Q - 1) + 1


def derive_public_key(secret: int) -> int:
    """Derive the public key from a Schnorr secret."""

    if not 0 < secret < Q:
        raise ValueError("Secret must lie in the multiplicative subgroup")
    return pow(G, secret, P)


def run_single_round(secret: int, public_key: int) -> Tuple[bool, SchnorrProof, int]:
    """Run a single round of the Schnorr protocol returning the transcript."""

    prover = SchnorrProver(secret)
    verifier = SchnorrVerifier(public_key)
    commitment = prover.commit()
    challenge = verifier.random_challenge()
    proof = prover.prove(challenge, commitment)
    return verifier.verify(commitment.commitment, proof), proof, commitment.commitment
