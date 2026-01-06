# Cryptography (Draft)

Aegis uses a custom container format with standard, well-reviewed cryptographic
primitives. This repository implements authenticated encryption for ACF v1+,
supports the v3 envelope model, and keeps the header in plaintext for
compatibility and streaming.

## Primitives

- AEAD: XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`)
- KDF: Argon2id (RustCrypto `argon2`)
- RNG: OS RNG via `rand_core::OsRng`
- Key agreement: X25519 (`x25519-dalek`)
- KDF (public-key wrapping): HKDF-SHA256 (`hkdf`, `sha2`)

## Argon2id parameters

Defaults are explicit and constant for v1 (not stored in the header):

- Memory: 64 MiB (65536 KiB)
- Iterations: 3
- Parallelism: 1
- Output length: 32 bytes (AEAD key length)

Default v2 parameters are stored in the header and differ by mode:

- Key file wrap: 64 MiB, 3 iterations, parallelism 1
- Password wrap: 128 MiB, 4 iterations, parallelism 1

Default v3 parameters are stored in the header and shared across all recipients.
If any recipient is password-based, password defaults apply; otherwise key-file
defaults apply.

## Key wrapping (v2)

ACF v2 never encrypts payloads directly with a password. Instead:

1) A random data key encrypts the payload.
2) A derived key (from password or key file) wraps the data key.
3) The wrapped data key is stored in the header.

The wrap uses XChaCha20-Poly1305 with a dedicated wrap nonce and an AAD
context string. This is for key wrapping only and is independent of payload
streaming.

Each container uses fresh random data keys, salts, and nonces to avoid
password reuse across files.

## Envelope model (v3)

ACF v3 encrypts the payload once with a random data key, then wraps that data
key for each recipient entry:

1) A random data key encrypts the payload.
2) A derived key (from password or key file) wraps the data key.
3) The header stores a recipients table of wrapped keys, one per recipient.

Recipient metadata (ID, type, wrap algorithm) is authenticated as AAD during
key wrapping to prevent substitution or downgrade of recipient fields. ACF v4
extends this model with public-key recipients.

## Public-key recipients (v4)

ACF v4 supports public-key recipients using X25519 + HKDF-SHA256. Each
container encryption generates a fresh ephemeral keypair:

1) Sender generates an ephemeral X25519 keypair.
2) For each recipient public key, derive a shared secret and HKDF to a wrap key.
3) Wrap the data key with XChaCha20-Poly1305.
4) Store recipient public key and ephemeral public key in the recipient entry.

Recipient metadata (ID, type, wrap algorithm, recipient public key, and
ephemeral public key) is authenticated as AAD during key wrapping.

## Recipient rotation

Rotation updates the recipients list while preserving the data key and payload
plaintext. The container is re-authenticated to bind the new header AAD to the
existing encrypted payload.

## Password vs key file

- Key files are high-entropy raw keys and should be preferred when possible.
- Passwords are lower entropy and must be strong and unique per file.
- Argon2id parameters for v2/v3 are stored in the header to avoid ambiguity.

## Nonce and streaming

ACF v1 uses the RustCrypto STREAM construction for XChaCha20-Poly1305.
The header stores a 20-byte stream nonce; the STREAM layer appends a 4-byte
counter/flag to form the full 24-byte AEAD nonce for each chunk.

## Header authentication

The ACF v1/v2/v3 header is plaintext but authenticated as AEAD AAD. This
protects cipher/KDF identifiers, salt, nonce, recipient metadata, and layout
information.

## Forward secrecy boundary

ACF v4 provides per-container ephemeral sender keys so data keys are never
reused and each encryption uses a unique shared secret. This does not provide
post-compromise protection if a recipient private key is captured and used
against stored containers; Aegis does not include one-time prekeys or a ratchet.

## Checksum vs. security

ACF v0 uses a CRC32 checksum for tamper detection only. CRC32 is not
cryptographically secure and does not provide authenticity or confidentiality.
An attacker can craft collisions and bypass detection.

## Threat boundaries

- ACF v1/v2/v3/v4 provides confidentiality and integrity of the encrypted payload.
- The header is authenticated but not encrypted.
- Key files are never embedded in containers.

## Key file format (v1)

Key files are binary and contain raw symmetric key material only:

- magic: `AEGK`
- version: u16
- key_len: u16
- key_bytes: N

## Public/private key file format (v1)

Public and private key files are binary and contain raw X25519 key material:

- public magic: `AEGP`
- private magic: `AEGS`
- version: u16
- key_len: u16 (must be 32)
- key_bytes: 32-byte X25519 key

## Current status

- No hardware-backed keys or secure elements.
- Multi-recipient encryption is supported for v3/v4.
- Recipient rotation is supported without changing the data key.
- No claims of being "unbreakable" or "perfectly secure".
