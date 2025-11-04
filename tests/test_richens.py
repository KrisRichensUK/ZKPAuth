import unittest

from zkpauth.richens import (
    issue_challenge,
    mint_capsule,
    respond_to_challenge,
    verify_attestation,
)


class TestRichensMethod(unittest.TestCase):
    def test_round_trip_attestation(self) -> None:
        essence = bytes.fromhex("7b8c08ed08f2dfac38c869bd832f6d3f5c4ab40d5433628b064afdf53977f9b7")
        capsule = mint_capsule(essence, context="test-context")
        challenge = issue_challenge(bits=64)
        proof = respond_to_challenge(essence, challenge, context="test-context")
        self.assertTrue(verify_attestation(capsule, challenge, proof))

    def test_invalid_capsule_rejected(self) -> None:
        essence = bytes.fromhex("77b2f9f74d4d9135d8639a4c447c6a7484cb69dd8269884ed5b50904d2f8d622")
        capsule = mint_capsule(essence)
        challenge = issue_challenge(bits=64)
        proof = respond_to_challenge(essence, challenge, context=capsule.context)
        tampered_capsule = type(capsule)(
            vector=capsule.vector,
            context="tampered-context",
            anchor=capsule.anchor,
            fingerprint=capsule.fingerprint,
        )
        self.assertFalse(verify_attestation(tampered_capsule, challenge, proof))


if __name__ == "__main__":
    unittest.main()
