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

:: Build the CLI and use the .exe directly
cargo build --release
.\target\release\aegis-cli.exe inspect C:\path\to\container.aegis

:: Stubs (not implemented yet)
.\target\release\aegis-cli.exe enc C:\path\to\input.bin C:\path\to\output.aegis
.\target\release\aegis-cli.exe dec C:\path\to\input.aegis C:\path\to\output.bin
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
