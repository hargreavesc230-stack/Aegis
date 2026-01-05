# Cryptography (Draft)

Aegis will use a custom container format with standard, well-reviewed
cryptographic primitives. This repository does not implement any encryption,
KDFs, or key storage yet.

## Principles

- Use established libraries and primitives (no proprietary ciphers).
- Provide clear versioning and algorithm agility.
- Keep cryptographic policy explicit and documented.
- Avoid claims of being "unbreakable" or "perfectly secure".

## Checksum vs. security

ACF v0 uses a CRC32 checksum for tamper detection only. CRC32 is not
cryptographically secure and does not provide authenticity or confidentiality.
An attacker can craft collisions and bypass detection.

## Future AEAD wrapping

The plan is to wrap ACF in authenticated encryption (AEAD) with well-reviewed
primitives. The AEAD layer will provide integrity, confidentiality, and
algorithm agility while keeping the container layout stable.

## Current status

- No encryption is implemented.
- No key derivation or key storage is implemented.
- No claims about confidentiality or integrity should be made.
