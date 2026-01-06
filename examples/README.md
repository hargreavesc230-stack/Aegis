# Examples

This folder contains example artifacts generated with mock data to demonstrate
the CLI workflow. The files are safe to share and do not contain real secrets.

Expected generated files (under `examples/generated`):

- `input.bin`, `meta.bin`: mock payload and metadata.
- `password.txt`: mock password used for password-mode examples.
- `packed.aegis`, `unpacked.bin`: pack/unpack example outputs.
- `recipient.key`: keyfile recipient.
- `recipient.pub`, `recipient.priv`: public/private keypair.
- `encrypted_keyfile.aegis`, `decrypted_keyfile.bin`: keyfile encryption roundtrip.
- `encrypted_password.aegis`, `decrypted_password.bin`: password encryption roundtrip.
- `encrypted_pubkey.aegis`, `decrypted_pubkey.bin`: public-key encryption roundtrip.

Minimal usage examples:

```
cargo run -p aegis-cli -- inspect examples\generated\encrypted_keyfile.aegis
cargo run -p aegis-cli -- dec examples\generated\encrypted_keyfile.aegis examples\generated\roundtrip.bin --recipient-key examples\generated\recipient.key
```

If you regenerate these artifacts locally, use mock values only and keep output
within `examples/generated` to avoid mixing with real data.
