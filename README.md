# Aegis

Aegis is a Rust workspace for a deterministic, streaming container format (ACF v0-v4) and CLI
tools that enforce explicit intent and fail-closed behavior.

## What Aegis is

- A streaming container format with strict parsing (ACF v0-v4).
- A CLI that refuses ambiguous input and avoids partial outputs.
- A toolkit for key files, password wrapping, and public-key recipients.

## What Aegis is not

- Not a key management system or password manager.
- Not a network protocol, transport, or synchronization system.
- Not a PKI or certificate authority.
- Not a post-compromise secrecy system (no ratchet or prekeys).

## Workspace layout

- `crates/aegis-core`: core utilities, errors, versioning, and constant-time helpers
- `crates/aegis-format`: binary container format parsing and writing (v0-v4)
- `crates/aegis-cli`: command-line interface with subcommands
- `crates/aegis-testkit`: shared test helpers and fixtures
- `crates/aegis-fuzzlite`: deterministic fuzz smoke runner (no external tooling)

## Security stance

- Uses standard, well-reviewed primitives (XChaCha20-Poly1305, Argon2id, X25519, HKDF-SHA256).
- No external audit has been performed yet.
- Password strength matters; weak passwords are vulnerable to offline guessing.
- Public-key recipients use per-container ephemeral keys (no post-compromise secrecy).

## Stability and compatibility contract

### Version support

- Inspectable: ACF v0-v4
- Decryptable: ACF v1-v4 (per-recipient constraints apply)
- Encryptable: ACF v0 (pack), ACF v3 (keyfile/password), ACF v4 (public-key recipients)
- ACF v1/v2 containers are never emitted by the CLI
- Unknown versions: hard error, no best-effort parsing (exit code 3)

### Stability guarantees

The following will not change silently:

- File header and chunk table layout for supported versions
- Magic values, IDs, and recipient type semantics
- Cryptographic primitives and AAD domains
- Exit code meanings and refusal rules

Any of the following require a major version bump:

- On-disk format changes (header, recipients, chunk layout)
- Cryptographic primitive swaps or new algorithms
- KDF parameter policy changes
- Exit code or refusal behavior changes

## Refusal and failure behavior

- Output files are never overwritten unless `--force` is provided (`pack`, `unpack`, `enc`, `rotate`).
- Decryption refuses to write if the output path already exists (no `--force` override).
- Mixed recipient types require `--allow-mixed-recipients`.
- Ambiguous or missing credential flags are rejected.
- Failures emit a single-line error, use stable exit codes, and leave no partial outputs.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 2    | CLI misuse or unsupported flag combinations |
| 3    | Format/validation error |
| 4    | I/O error |
| 5    | Cryptographic error or authentication failure |

## Building on Windows (cmd.exe)

Open `cmd.exe` in the repository root and run:

```
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Release gate (cmd.exe)

`scripts\check.bat` is the authoritative release gate. A release is invalid unless it passes.
The script runs formatting, clippy, tests, fuzz-lite, happy-path integration, refusal tests,
tamper/corruption checks, stress cases, and cleanup verification using mock data only.

```
scripts\check.bat
```

## Fuzzing (fuzz-lite)

`aegis-fuzzlite` runs a deterministic, dependency-free fuzz smoke test in
CI and `scripts\check.bat`.

```
cargo run -p aegis-fuzzlite -- --iters 1000 --max-len 4096
```

## CLI examples

```
:: Inspect a container (with checksum verification)
cargo run -p aegis-cli -- inspect C:\path\to\container.aegis

:: Pack data into a container
cargo run -p aegis-cli -- pack C:\path\to\input.bin C:\path\to\output.aegis

:: Pack with metadata
cargo run -p aegis-cli -- pack C:\path\to\input.bin C:\path\to\output.aegis --metadata C:\path\to\meta.bin

:: Unpack the data chunk
cargo run -p aegis-cli -- unpack C:\path\to\input.aegis C:\path\to\output.bin

:: Generate a key file
cargo run -p aegis-cli -- keygen C:\path\to\aegis.key

:: Generate a public/private keypair (X25519)
cargo run -p aegis-cli -- keygen --public C:\path\to\recipient.pub --private C:\path\to\recipient.priv

:: Encrypt with multiple recipient types (explicitly allowed)
cargo run -p aegis-cli -- enc C:\path\to\input.bin C:\path\to\output.aegis --recipient-key C:\path\to\aegis.key --recipient-password --allow-mixed-recipients

:: Encrypt with a public-key recipient (ACF v4)
cargo run -p aegis-cli -- enc C:\path\to\input.bin C:\path\to\output.aegis --recipient-pubkey C:\path\to\recipient.pub

:: Decrypt with a key file (ACF v3/v4)
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --recipient-key C:\path\to\aegis.key

:: Decrypt with a password (ACF v3/v4)
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --recipient-password

:: Decrypt with a private key (ACF v4)
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --private-key C:\path\to\recipient.priv

:: List recipients in a container
cargo run -p aegis-cli -- list-recipients C:\path\to\output.aegis

:: Rotate recipients (add/remove without re-encrypting the payload)
cargo run -p aegis-cli -- rotate C:\path\to\output.aegis --output C:\path\to\rotated.aegis --auth-key C:\path\to\aegis.key --add-recipient-key C:\path\to\new.key --remove-recipient 1
```

Logs are off by default. To enable logs:

```
set RUST_LOG=info
.\target\release\aegis-cli.exe inspect C:\path\to\container.aegis
```
