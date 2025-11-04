"""Command line interface for the zero-knowledge authentication demo."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from zkpauth.auth import authenticate, register_user
from zkpauth.richens import (
    RichensCapsule,
    RichensProof,
    issue_challenge,
    mint_capsule,
    respond_to_challenge,
    verify_attestation,
)
from zkpauth.store import UserStore

DEFAULT_STORE = Path("users.json")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--store",
        default=str(DEFAULT_STORE),
        help="Location of the JSON store (default: users.json)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Register a new credential")
    register_parser.add_argument(
        "alias",
        nargs="?",
        help="Optional human friendly alias for the credential",
    )
    register_parser.add_argument(
        "--secret",
        help=(
            "Hex-encoded private secret. If omitted a random value is generated and "
            "printed to stdout."
        ),
    )

    login_parser = subparsers.add_parser("login", help="Authenticate a credential")
    login_parser.add_argument(
        "identifier",
        help="Alias or credential id depending on the selected mode",
    )
    login_parser.add_argument("secret", help="Hex-encoded private secret")
    login_group = login_parser.add_mutually_exclusive_group()
    login_group.add_argument(
        "--alias",
        dest="by_alias",
        action="store_true",
        help="Interpret the identifier as an alias (default)",
    )
    login_group.add_argument(
        "--credential",
        dest="by_alias",
        action="store_false",
        help="Interpret the identifier as a credential id",
    )
    login_parser.set_defaults(by_alias=True)

    richens_mint = subparsers.add_parser(
        "richens-mint",
        help="Mint a Richens capsule representing a stateless identity",
    )
    richens_mint.add_argument(
        "--essence",
        help=(
            "Hex-encoded personal essence. If omitted a random value is generated "
            "and printed alongside the capsule."
        ),
    )
    richens_mint.add_argument(
        "--context",
        default="richens-global",
        help="Application context string for the Richens method",
    )
    richens_mint.add_argument(
        "--output",
        help="Optional file path to store the capsule JSON",
    )

    richens_login = subparsers.add_parser(
        "richens-login",
        help="Perform a Richens attestation using a capsule and essence",
    )
    richens_login.add_argument("capsule", help="Path to the capsule JSON data")
    richens_login.add_argument(
        "--essence",
        required=True,
        help="Hex-encoded personal essence retained by the participant",
    )
    richens_login.add_argument(
        "--challenge",
        help="Optional hex encoded challenge. If omitted a fresh challenge is issued.",
    )

    return parser.parse_args(argv)


def load_store(path: str) -> UserStore:
    return UserStore(path)


def main(argv: list[str] | None = None) -> int:
    namespace = parse_args(argv or sys.argv[1:])
    store = load_store(namespace.store)

    if namespace.command == "register":
        secret_value = int(namespace.secret, 16) if namespace.secret else None
        payload = register_user(store, namespace.alias, secret_value)
        print(json.dumps(payload, indent=2))
        return 0

    if namespace.command == "login":
        secret_value = int(namespace.secret, 16)
        result = authenticate(
            store,
            namespace.identifier,
            secret_value,
            use_alias=namespace.by_alias,
        )
        print(json.dumps(result, indent=2))
        return 0

    if namespace.command == "richens-mint":
        essence = (
            bytes.fromhex(namespace.essence)
            if namespace.essence
            else secrets.token_bytes(32)
        )
        capsule = mint_capsule(essence, context=namespace.context)
        payload = {
            "capsule": capsule.to_dict(),
            "persona": capsule.persona,
            "essence": essence.hex(),
        }
        if namespace.output:
            Path(namespace.output).write_text(json.dumps(payload["capsule"], indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if namespace.command == "richens-login":
        capsule_payload = json.loads(Path(namespace.capsule).read_text(encoding="utf-8"))
        if "vector" in capsule_payload:
            capsule_data = capsule_payload
        elif "capsule" in capsule_payload:
            capsule_data = capsule_payload["capsule"]
        else:
            print("Capsule file is missing Richens data", file=sys.stderr)
            return 1
        try:
            capsule = RichensCapsule.from_dict(capsule_data)
        except ValueError as exc:  # pragma: no cover - CLI validation
            print(f"Invalid capsule: {exc}", file=sys.stderr)
            return 1
        if namespace.challenge:
            challenge = int(namespace.challenge, 16)
        else:
            challenge = issue_challenge()
        if challenge <= 0:
            print("Challenge must be greater than zero", file=sys.stderr)
            return 1
        essence = bytes.fromhex(namespace.essence)
        proof = respond_to_challenge(essence, challenge, context=capsule.context)
        verified = verify_attestation(capsule, challenge, proof)
        payload = {
            "challenge": hex(challenge),
            "capsule_persona": capsule.persona,
            "proof": proof.to_dict(),
            "verified": verified,
        }
        print(json.dumps(payload, indent=2))
        return 0

    raise RuntimeError("Unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
