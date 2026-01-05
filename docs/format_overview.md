# Format Overview (ACF v0/v1)

Aegis Container Format (ACF) is a deterministic, streaming-first binary layout
with strict parsing rules. v0 is unencrypted; v1 adds authenticated encryption
(XChaCha20-Poly1305) while keeping the header in plaintext.

## Global rules

- Endianness: little-endian
- Fixed-width integers only
- No implicit padding
- All offsets and lengths validated before use
- Unknown versions MUST error

## High-level layout

```
[ FileHeader ]
[ ChunkTable ]
[ ChunkData... ]
[ Footer ]
```

For v1, the `ChunkTable`, `ChunkData`, and `Footer` are encrypted as a single
payload. Only the header is plaintext and authenticated as AAD.

## FileHeader (base, fixed-size)

Length: 36 bytes

| Offset | Size | Field              | Description                             |
|--------|------|--------------------|-----------------------------------------|
| 0      | 8    | magic              | ASCII `AEGIS\0\0\0`                   |
| 8      | 2    | version            | v0 = 0, v1 = 1                          |
| 10     | 2    | header_len         | Total header length in bytes            |
| 12     | 4    | flags              | Reserved, must be 0                     |
| 16     | 4    | chunk_count        | Number of chunk table entries           |
| 20     | 8    | chunk_table_offset | Must equal header_len                   |
| 28     | 8    | footer_offset      | Byte offset to footer (plaintext)       |

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

## ChunkTable

Each entry is 24 bytes. Entries MUST be sorted and contiguous by offset.

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
