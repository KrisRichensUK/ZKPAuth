# ZKPAuth
Zero Knowledge Authentication.

Zero-knowledge authentication. This
project demonstrates how a user can authenticate to a verifier without ever revealing
their long-lived secret. No specialised hardware is required – everything runs purely
in software.

## Features

- 2048-bit safe-prime group parameters from RFC 3526.
- Multi-round Schnorr identification with configurable challenge size.
- JSON-backed credential store for quick experimentation.
- Command line interface for registering and authenticating credentials.
- **Richens method** – a stateless, database-free attestation ritual using cubic
  identities instead of usernames or passwords.
- FastAPI service that exposes a passwordless challenge/response flow for the web.

## Quickstart

1. **Install dependencies** (FastAPI/uvicorn are optional unless you want the web API):

   ```bash
   pip install -r requirements.txt
   ```

2. **Register a credential** – provide an alias if you want a human readable label. A
   deterministic credential identifier is generated from the public key, so you can omit
   the alias entirely and still authenticate later. A secret will be generated if you
   omit `--secret`:

   ```bash
   python zkp_auth.py register alice
   ```

   Example output:

   ```json
   {
     "credential_id": "3b73e0e0...",
     "alias": "alice",
     "public_key": "0x4a8...",
     "secret": "0x9f2..."
   }
   ```

   Save the secret securely – it never leaves the prover during authentication.

3. **Authenticate** with the stored secret. Use the alias by default or switch to the
   credential identifier using `--credential` if you prefer to avoid usernames entirely:

   ```bash
   python zkp_auth.py login alice 0x9f2...
   python zkp_auth.py login 3b73e0e0... 0x9f2... --credential
   ```

   Successful authentication returns the transcript of the zero-knowledge interaction
   so you can audit each round:

   ```json
   {
     "credential_id": "3b73e0e0...",
     "alias": "alice",
     "rounds": [
       {
         "commitment": "0x...",
         "challenge": "0x...",
         "response": "0x..."
       },
       {
         "commitment": "0x...",
         "challenge": "0x...",
         "response": "0x..."
       }
     ],
     "success": true
   }
   ```

4. **Explore programmatically** using the Python API:

   ```python
   from zkpauth import UserStore, authenticate, register_user

   store = UserStore("users.json")
   registration = register_user(store, "bob")
   result = authenticate(store, registration["credential_id"], int(registration["secret"], 16), use_alias=False)
   assert result["success"]
   ```

## The Richens method – stateless personhood attestation

The Richens method is a brand new handshake that proves the presence of a living
participant without usernames, passwords, or database lookups. A participant
distils an **essence** – a private mathematical seed that never leaves their
device – and from it mints a _capsule_. The capsule is safe to share: it only
contains cubic commitments that trace the participant's personal spectrum. To
log in, the participant answers a one-off challenge with a Richens proof. The
verifier checks only the capsule and the proof; no prior record or storage is
required.

### Mint an essence capsule

```bash
python zkp_auth.py richens-mint --output alice.richens.json
```

Example output (essence shortened for clarity):

```json
{
  "capsule": {
    "vector": [
      "0x2c0...",
      "0x574...",
      "0x88d..."
    ],
    "context": "richens-global",
    "anchor": "0x7e1...",
    "fingerprint": "f1d77d2c0d66fe7c7df5d90db43a421b9f7c0e70f2ac8eb5a4c3694f85d6b91b"
  },
  "persona": "f1d77d2c0d66fe7c7df5d90d",
  "essence": "5f91..."
}
```

The capsule JSON can be published anywhere – it is reusable and stateless.
Protect the essence locally; it represents the participant's personhood.

### Log in with a capsule

```bash
python zkp_auth.py richens-login alice.richens.json --essence 5f91...
```

Output:

```json
{
  "challenge": "0x51c...",
  "capsule_persona": "f1d77d2c0d66fe7c7df5d90d",
  "proof": {
    "response": "0x4e3...",
    "orbital": "0x9c8...",
    "parity": "d181..."
  },
  "verified": true
}
```

The verifier never touches a database: it rebuilds expectations entirely from
the supplied capsule. The Richens polynomial response interlocks with the
capsule's cubic commitments, so only the original essence holder can satisfy the
equations.

## Tests

Unit tests cover both the classical Schnorr flow and the experimental Richens
method. Run the suite with:

```bash
python -m unittest discover -s tests
```

## Zero-knowledge authentication for the web

The `zkpauth.server` module exposes the same Schnorr flow over HTTP so a web property can
issue challenges and verify responses without traditional usernames or passwords.

1. **Start the server** (the default store is `users.json`):

   ```bash
   uvicorn zkpauth.server:app --reload
   ```

2. **Register a credential** using the `/register` endpoint. This returns the secret the
   client must hold, along with the credential identifier the website will remember.

3. **Perform a login** by executing the two-step dance:

   - `POST /login/start` with the credential identifier and the Schnorr commitment.
     The server returns a random challenge plus a short-lived session id.
   - `POST /login/finish` with the response computed by the prover. The server verifies
     the transcript and returns whether the login succeeded.

Client automation can be built in any language capable of modular exponentiation and
HTTP requests. The provided CLI demonstrates how to derive commitments and responses
without ever disclosing the long-term secret.

## Notes

- The implementation is intended for educational use; it omits production features
  such as rate limiting and secure secret storage.
- Removing `users.json` resets the demonstration environment.
- Increase the number of rounds in `zkpauth/constants.py` for higher security margins.
