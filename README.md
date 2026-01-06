# Aegis

Aegis is a Rust workspace for building a secure, streaming container format and CLI tools.
This repository focuses on correctness, hardening, and Windows-ready tooling with
standard cryptography.

## Workspace layout

- `crates/aegis-core`: core utilities, errors, versioning, and constant-time helpers
- `crates/aegis-format`: binary container format parsing and writing (v0-v4)
- `crates/aegis-cli`: command-line interface with subcommands
- `crates/aegis-testkit`: shared test helpers and fixtures
- `crates/aegis-fuzzlite`: deterministic fuzz smoke runner (no external tooling)

## Security stance

- Not production-ready and not audited.
- No claims of being "unbreakable" or "military-grade".
- The format uses standard, well-reviewed cryptography with key wrapping.
- Public-key recipients use X25519 + HKDF-SHA256 for shared secret derivation.
- Public-key recipients use per-container ephemeral keys, but there is no post-compromise secrecy.
- Security-sensitive material is excluded from version control by default.
- Password strength matters; weak passwords are vulnerable to offline guessing.

## Building on Windows (cmd.exe)

Open `cmd.exe` in the repository root and run:

```
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Full system check (cmd.exe)

The integration script `scripts\check.bat` runs formatting, clippy, tests, fuzz
smoke checks, and end-to-end CLI checks. It creates mock inputs and keys,
exercises `pack`, `inspect`, `unpack`, `keygen`, `enc`, `dec`,
`list-recipients`, and `rotate`, verifies roundtrips, and ensures wrong-key,
wrong-password, corrupted ciphertext, public-key misuse, and rotation failures. For
automation, it uses `AEGIS_PASSWORD` and `AEGIS_PASSWORD_CONFIRM`.

```
scripts\check.bat
```

## Fuzzing (fuzz-lite)

`aegis-fuzzlite` runs a deterministic, dependency-free fuzz smoke test in
CI and `scripts\check.bat`. It generates adversarial inputs and feeds them
into the parser, decrypt, rotation, and public-key paths.

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

:: Encrypt with multiple recipients (ACF v3)
cargo run -p aegis-cli -- enc C:\path\to\input.bin C:\path\to\output.aegis --recipient-key C:\path\to\aegis.key --recipient-password

:: Encrypt with a public-key recipient (ACF v4)
cargo run -p aegis-cli -- enc C:\path\to\input.bin C:\path\to\output.aegis --recipient-pubkey C:\path\to\recipient.pub

:: Decrypt with a key file (ACF v3)
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --recipient-key C:\path\to\aegis.key

:: Decrypt with a password (ACF v3)
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --recipient-password

:: Decrypt with a private key (ACF v4)
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --private-key C:\path\to\recipient.priv

:: List recipients in a container
cargo run -p aegis-cli -- list-recipients C:\path\to\output.aegis

:: Rotate recipients (add/remove without re-encrypting the payload)
cargo run -p aegis-cli -- rotate C:\path\to\output.aegis --output C:\path\to\rotated.aegis --auth-key C:\path\to\aegis.key --add-recipient-key C:\path\to\new.key --remove-recipient 1

:: Build the CLI and use the .exe directly
cargo build --release
.\target\release\aegis-cli.exe inspect C:\path\to\container.aegis
```

To enable logs:

```
set RUST_LOG=info
.\target\release\aegis-cli.exe inspect C:\path\to\container.aegis
```

## Roadmap (high level)

- Formalize the container format specification and versioning policy
- Expand CLI with batch tooling, verification, and safe defaults
- Add prekey/ratchet support for post-compromise secrecy (no PKI yet)
- Harden envelope rotation UX and recipient discovery
- Establish an external security review before production use
