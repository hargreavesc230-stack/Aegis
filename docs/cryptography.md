# Cryptography (Draft)

Aegis uses a custom container format with standard, well-reviewed cryptographic
primitives. This repository implements authenticated encryption for ACF v1 and
keeps the header in plaintext for compatibility and streaming.

## Primitives

- AEAD: XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`)
- KDF: Argon2id (RustCrypto `argon2`)
- RNG: OS RNG via `rand_core::OsRng`

## Argon2id parameters

Defaults are explicit and constant for v1:

- Memory: 64 MiB (65536 KiB)
- Iterations: 3
- Parallelism: 1
- Output length: 32 bytes (AEAD key length)

## Nonce and streaming

ACF v1 uses the RustCrypto STREAM construction for XChaCha20-Poly1305.
The header stores a 20-byte stream nonce; the STREAM layer appends a 4-byte
counter/flag to form the full 24-byte AEAD nonce for each chunk.

## Header authentication

The ACF v1 header is plaintext but authenticated as AEAD AAD. This protects
cipher/KDF identifiers, salt, nonce, and layout metadata from tampering.

## Checksum vs. security

ACF v0 uses a CRC32 checksum for tamper detection only. CRC32 is not
cryptographically secure and does not provide authenticity or confidentiality.
An attacker can craft collisions and bypass detection.

## Threat boundaries

- ACF v1 provides confidentiality and integrity of the encrypted payload.
- The header is authenticated but not encrypted.
- Key files are never embedded in containers.

## Key file format (v1)

Key files are binary and contain raw symmetric key material only:

- magic: `AEGK`
- version: u16
- key_len: u16
- key_bytes: N

## Current status

- No hardware-backed keys or secure elements.
- No multi-recipient encryption.
- No claims of being "unbreakable" or "perfectly secure".
