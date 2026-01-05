# Aegis

Aegis is a Rust workspace for building a secure, streaming container format and CLI tools.
This repository is focused on architecture, correctness, and platform-ready scaffolding.
Encryption and key management are intentionally not implemented yet.

## Workspace layout

- `crates/aegis-core`: core utilities, errors, versioning, and constant-time helpers
- `crates/aegis-format`: binary container format parsing and writing (no crypto)
- `crates/aegis-cli`: command-line interface with subcommands
- `crates/aegis-testkit`: shared test helpers and fixtures

## Security stance

- Not production-ready and not audited.
- No claims of being "unbreakable" or "military-grade".
- The format will use standard, well-reviewed cryptography in later phases.
- Security-sensitive material is excluded from version control by default.

## Building on Windows (cmd.exe)

Open `cmd.exe` in the repository root and run:

```
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Full system check (cmd.exe)

The integration script `scripts\check.bat` runs formatting, clippy, tests, and
end-to-end CLI checks. It creates mock inputs and keys, exercises `pack`,
`inspect`, `unpack`, `keygen`, `enc`, and `dec`, verifies roundtrips, and
ensures wrong-key and corrupted ciphertext failures.

```
scripts\check.bat
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

:: Encrypt and decrypt (ACF v1)
cargo run -p aegis-cli -- enc C:\path\to\input.bin C:\path\to\output.aegis --key C:\path\to\aegis.key
cargo run -p aegis-cli -- dec C:\path\to\output.aegis C:\path\to\roundtrip.bin --key C:\path\to\aegis.key

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
- Implement authenticated encryption using standard cryptographic primitives
- Add streaming key derivation and metadata integrity
- Expand CLI with batch tooling, verification, and safe defaults
- Establish an external security review before production use
