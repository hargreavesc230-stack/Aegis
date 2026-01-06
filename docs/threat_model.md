# Threat Model

## Status

Aegis is in its initial public release. It has not been externally audited.
Use it with caution and validate it against your threat model.

## Assets

- Confidentiality of encrypted payloads (ACF v1-v4)
- Integrity of headers, recipient metadata, and payloads
- Availability of CLI operations on hostile inputs
- Correct enforcement of recipient access controls (v3/v4)

## Attacker models

- Local attacker with read/write access to container files
- Remote attacker supplying crafted or malicious containers
- Offline attacker attempting password guessing
- Insider with access to one recipient credential
- Post-compromise attacker with a leaked recipient private key

## Trust boundaries

- Input container files are untrusted
- CLI arguments, paths, and environment variables are untrusted
- Output files may be consumed by other systems

## Security goals

- Reject malformed or truncated inputs safely and deterministically
- Preserve confidentiality and integrity under active tampering
- Fail closed without partial plaintext output
- Avoid hangs or unbounded resource growth on hostile input

## Non-goals

- Side-channel resistance beyond best-effort handling
- Key management, storage, or rotation policies outside the container
- PKI, certificate validation, or automated key distribution
- Post-compromise secrecy or forward secrecy for stored containers
- Hiding header metadata (headers remain plaintext)

## Assumptions

- The OS RNG is available and functioning correctly.
- Users provide strong passwords for password-based recipients.
- Private keys and key files are stored securely by the user.

## Mitigations

- Authenticated encryption with standard primitives (ACF v1-v4)
- Key wrapping for password and multi-recipient encryption (ACF v2-v4)
- Recipient metadata authenticated as AAD (v3/v4)
- Strict bounds checks and validation in the parser
