# Threat Model (Draft)

## Status

This threat model is an evolving draft. Aegis is not production-ready and has
not been externally audited.

## Assets

- Confidentiality of container payloads (ACF v1-v3)
- Integrity of container metadata and payloads
- Availability of the CLI tools and container processing
- Recipient lists and key wrapping metadata (ACF v3)

## Adversaries

- Local attacker with read/write access to containers
- Remote attacker who can provide crafted container files
- Malware or untrusted software on the same host
- Offline attacker attempting password brute-force
- Insider with access to one recipient credential

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
- Tamper with recipient entries or wrap metadata (ACF v3)
- Remove or reorder recipients to break access controls (ACF v3)
- Exhaustively guess weak passwords against captured containers

## Goals

- Reject malformed or truncated inputs safely
- Provide clear, structured errors without panics
- Maintain strict bounds checks on all binary parsing
- Ensure AEAD authentication fails cleanly on tampering
- Make offline guessing costly via Argon2id parameters

## Non-goals (current)

- Resistance to side-channel leakage beyond best-effort handling
- Key management, KDF tuning by user, or hardware-backed secrets
- Public-key recipients or PKI-backed sharing

## Mitigations (current)

- Authenticated encryption with standard primitives (ACF v1-v3)
- Key wrapping for password-based and multi-recipient encryption (ACF v2/v3)
- Domain-separated metadata and payload integrity
- Explicit versioning and format negotiation
