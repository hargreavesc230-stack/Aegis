# Format Overview (ACF v0-v4)

Aegis Container Format (ACF) is a deterministic, streaming-first binary layout
with strict parsing rules. v0 is unencrypted; v1 adds authenticated encryption
(XChaCha20-Poly1305) while keeping the header in plaintext. v2 adds key wrapping
so passwords never directly encrypt payloads. v3 introduces a recipients table
for multi-recipient envelopes. v4 extends recipients with public-key entries.

## Global rules

- Endianness: little-endian
- Fixed-width integers only
- No implicit padding
- All offsets and lengths validated before use
- Unknown versions MUST error

## Compatibility contract

### Version support

- Inspectable: v0-v4
- Decryptable: v1-v4
- Encryptable: v0 (pack), v3 (keyfile/password), v4 (public-key recipients)
- ACF v1/v2 containers are never emitted by the CLI
- Unknown versions: hard error, no best-effort parsing

Inspect behavior: `aegis-cli inspect` reads the header and fails closed on
unknown or malformed versions without attempting best-effort parsing.

### Stability guarantees

- The on-disk layout for v0-v4 will not change silently.
- Magic values, IDs, and recipient semantics are stable.
- Cryptographic primitives and AAD domains are stable.
- Any format change requires a major version bump.

## High-level layout

```
[ FileHeader ]
[ ChunkTable ]
[ ChunkData... ]
[ Footer ]
```

For v1-v4, the `ChunkTable`, `ChunkData`, and `Footer` are encrypted as a single
payload. Only the header is plaintext and authenticated as AAD. Offsets and
lengths in the header and chunk table refer to the plaintext layout, not the
ciphertext layout.

## FileHeader (base, fixed-size)

Length: 36 bytes

| Offset | Size | Field              | Description                             |
|--------|------|--------------------|-----------------------------------------|
| 0      | 8    | magic              | ASCII `AEGIS\0\0\0`                   |
| 8      | 2    | version            | v0 = 0, v1 = 1, v2 = 2, v3 = 3, v4 = 4 |
| 10     | 2    | header_len         | Total header length in bytes            |
| 12     | 4    | flags              | Reserved, must be 0                     |
| 16     | 4    | chunk_count        | Number of chunk table entries           |
| 20     | 8    | chunk_table_offset | Must equal header_len                   |
| 28     | 8    | footer_offset      | Byte offset to footer in plaintext layout |

Rules:

- magic and version validated immediately
- header_len enables future extension
- flags != 0 MUST error

## Header extensions (v1)

Immediately after the base header:

| Field      | Size | Description                |
|------------|------|----------------------------|
| cipher_id  | 2    | 0x0001 = XChaCha20-Poly1305|
| kdf_id     | 2    | 0x0001 = Argon2id           |
| salt_len   | 2    | Length of salt bytes        |
| salt_bytes | N    | Salt for Argon2id           |
| nonce_len  | 2    | Length of nonce bytes       |
| nonce      | N    | Stream nonce (20 bytes for v1) |

The header is authenticated as AEAD AAD in v1.

For v1 streaming, the stored nonce is 20 bytes. The STREAM construction
appends a 4-byte counter/flag to form the 24-byte XChaCha20-Poly1305 nonce.

## Header extensions (v2)

v2 adds key wrapping and KDF parameters. The header stores:

| Field            | Size | Description                         |
|------------------|------|-------------------------------------|
| cipher_id        | 2    | 0x0001 = XChaCha20-Poly1305         |
| kdf_id           | 2    | 0x0001 = Argon2id                   |
| kdf_memory_kib   | 4    | Argon2id memory cost (KiB)          |
| kdf_iterations   | 4    | Argon2id iterations                 |
| kdf_parallelism  | 4    | Argon2id parallelism                |
| salt_len         | 2    | Length of salt bytes                |
| salt_bytes       | N    | Salt for Argon2id                   |
| nonce_len        | 2    | Length of stream nonce bytes        |
| nonce            | N    | Stream nonce (20 bytes for v2)      |
| wrap_type        | 2    | 0x0001 = Keyfile, 0x0002 = Password |
| wrapped_key_len  | 2    | Length of wrapped key bytes         |
| wrapped_key      | N    | Wrapped data key bytes              |

Wrapped key bytes are encoded as:

```
u16 wrap_nonce_len
u8  wrap_nonce[wrap_nonce_len]   (24 bytes for v2)
u8  ciphertext[data_key_len + tag]
```

The header is authenticated as AEAD AAD in v2.

## Header extensions (v3)

v3 replaces the single wrapped key with a recipients table. The header stores:

| Field            | Size | Description                         |
|------------------|------|-------------------------------------|
| cipher_id        | 2    | 0x0001 = XChaCha20-Poly1305         |
| kdf_id           | 2    | 0x0001 = Argon2id                   |
| kdf_memory_kib   | 4    | Argon2id memory cost (KiB)          |
| kdf_iterations   | 4    | Argon2id iterations                 |
| kdf_parallelism  | 4    | Argon2id parallelism                |
| salt_len         | 2    | Length of salt bytes                |
| salt_bytes       | N    | Salt for Argon2id                   |
| nonce_len        | 2    | Length of stream nonce bytes        |
| nonce            | N    | Stream nonce (20 bytes for v3)      |
| recipient_count  | 2    | Number of recipient entries         |
| recipients       | N    | Repeated recipient entries          |

Recipient entries:

| Field              | Size | Description                         |
|--------------------|------|-------------------------------------|
| recipient_id       | 4    | Unique ID per recipient             |
| recipient_type     | 2    | 0x0001 = Keyfile, 0x0002 = Password |
| wrap_alg           | 2    | 0x0001 = XChaCha20-Poly1305         |
| wrapped_key_len    | 4    | Length of wrapped key bytes         |
| wrapped_key        | N    | Wrapped data key bytes              |

Recipient metadata is authenticated as AAD during key wrapping.

Rules:

- At least one recipient is required
- Recipient IDs must be unique
- Unknown recipient types or wrap algorithms MUST error
- wrapped_key_len MUST be bounded and validated before use

## Header extensions (v4)

v4 keeps the v3 header layout but extends recipients for public-key entries.

Recipient entries (v4):

| Field              | Size | Description                         |
|--------------------|------|-------------------------------------|
| recipient_id       | 4    | Unique ID per recipient             |
| recipient_type     | 2    | 0x0001 = Keyfile, 0x0002 = Password, 0x0003 = PublicKey |
| wrap_alg           | 2    | 0x0001 = XChaCha20-Poly1305         |
| recipient_pubkey   | 32   | X25519 public key (public-key only) |
| ephemeral_pubkey   | 32   | Sender ephemeral pubkey (public-key only) |
| wrapped_key_len    | 4    | Length of wrapped key bytes         |
| wrapped_key        | N    | Wrapped data key bytes              |

For keyfile/password recipients, the public-key fields are omitted.
Public-key entries include both keys and are authenticated as AAD; the
ephemeral key must be freshly generated per container.

## ChunkTable

Each entry is 24 bytes. Entries MUST be sorted and contiguous by offset.
Offsets are expressed in the plaintext layout for all versions.

| Offset | Size | Field      | Description                    |
|--------|------|------------|--------------------------------|
| 0      | 4    | chunk_id   | Logical chunk identifier       |
| 4      | 2    | chunk_type | Enumerated type (see below)    |
| 6      | 2    | flags      | Reserved for future use        |
| 8      | 8    | offset     | Absolute offset in plaintext   |
| 16     | 8    | length     | Chunk length in bytes          |

Chunk types:

- 0x0001 = Data
- 0x0002 = Metadata
- 0xFFFF = Reserved

Rules:

- offsets must point forward, starting immediately after the chunk table
- chunks MUST NOT overlap
- gaps are rejected (no implicit padding)

## ChunkData

Raw bytes with no interpretation. Data is read and written using streaming I/O
and should not be fully loaded into memory by default.

## Footer

- v0: checksum footer (CRC32) for tamper detection only
- v1: fixed-length footer (no checksum) inside encrypted payload
- v2-v4: same as v1 (inside encrypted payload)
