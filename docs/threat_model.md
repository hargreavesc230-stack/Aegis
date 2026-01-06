# Threat Model (Draft)

## Status

This threat model is an evolving draft. Aegis is not production-ready and has
not been externally audited.

## Assets

- Confidentiality of container payloads (ACF v1-v4)
- Integrity of container metadata and payloads
- Availability of the CLI tools and container processing
- Recipient lists and key wrapping metadata (ACF v3-v4)

## Adversaries

- Local attacker with read/write access to containers
- Remote attacker who can provide crafted container files
- Malware or untrusted software on the same host
- Offline attacker attempting password brute-force
- Insider with access to one recipient credential
- Post-compromise attacker with a leaked recipient private key

## Trust boundaries

- Input container files are untrusted
- Output files may be consumed by other systems
- CLI environment variables and paths are untrusted

## Attack surfaces

- Container parsing and validation logic
- CLI argument handling and file I/O
- Recipient rotation and envelope management
- Error messages that could leak metadata

## Attacker goals

- Tamper with container bytes to alter data or metadata
- Truncate containers to remove trailing data
- Reorder or overlap chunks to confuse parsers
- Substitute ciphertext to induce decryption failures
- Tamper with recipient entries or wrap metadata (ACF v3-v4)
- Remove or reorder recipients to break access controls (ACF v3-v4)
- Exhaustively guess weak passwords against captured containers
- Substitute recipient public keys or ephemeral keys (ACF v4)
- Attempt decryption after private-key compromise

## Goals

- Reject malformed or truncated inputs safely
- Provide clear, structured errors without panics
- Maintain strict bounds checks on all binary parsing
- Ensure AEAD authentication fails cleanly on tampering
- Make offline guessing costly via Argon2id parameters

## Non-goals (current)

- Resistance to side-channel leakage beyond best-effort handling
- Key management, KDF tuning by user, or hardware-backed secrets
- PKI / certificate chains or automated key distribution
- Post-compromise secrecy for stored containers

## Mitigations (current)

- Authenticated encryption with standard primitives (ACF v1-v4)
- Key wrapping for password-based and multi-recipient encryption (ACF v2-v4)
- Domain-separated metadata and payload integrity
- Public-key recipients with per-container ephemeral keys (ACF v4)
- Explicit versioning and format negotiation
