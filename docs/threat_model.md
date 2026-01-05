# Threat Model (Draft)

## Status

This threat model is an evolving draft. Aegis is not production-ready and has
no cryptography implemented yet.

## Assets

- Confidentiality of container payloads
- Integrity of container metadata and payloads
- Availability of the CLI tools and container processing

## Adversaries

- Local attacker with read access to containers
- Remote attacker who can provide crafted container files
- Malware or untrusted software on the same host

## Trust boundaries

- Input container files are untrusted
- Output files may be consumed by other systems
- CLI environment variables and paths are untrusted

## Attack surfaces

- Container parsing and validation logic
- CLI argument handling and file I/O
- Error messages that could leak metadata

## Attacker goals (added)

- Tamper with container bytes to alter data or metadata
- Truncate containers to remove trailing data
- Reorder or overlap chunks to confuse parsers

## Goals

- Reject malformed or truncated inputs safely
- Provide clear, structured errors without panics
- Maintain strict bounds checks on all binary parsing

## Non-goals (current)

- Resistance to advanced cryptographic attacks (no crypto yet)
- Side-channel hardening beyond best-effort comparisons
- Key management, KDFs, or hardware-backed secrets

## Mitigations (planned)

- Authenticated encryption with standard primitives
- Domain-separated metadata and payload integrity
- Explicit versioning and format negotiation
