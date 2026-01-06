# Contributing to Aegis

Thank you for your interest in contributing. This project is security-focused and
aims for clear, reviewed changes.

## Development setup (Windows)

Use `cmd.exe` in the repository root:

```
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
scripts\check.bat
```

## Guidelines

- Keep changes small and reviewable.
- Prefer clear, explicit error handling over implicit behavior.
- Avoid introducing new cryptography without prior discussion.
- Document security-impacting changes.
- Ensure code compiles and tests pass on Windows.

## Submitting changes

1. Fork the repo and create a feature branch.
2. Make your changes with tests where appropriate.
3. Run the checks listed above.
4. Open a pull request with a clear description and rationale.

## Code style

- Rust edition 2021
- `rustfmt` and `clippy` clean
- Avoid unsafe code unless explicitly justified and reviewed
