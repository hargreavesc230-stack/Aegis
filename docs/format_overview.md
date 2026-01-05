# Format Overview (ACF v0)

Aegis Container Format (ACF) v0 is a deterministic, streaming-first binary
layout designed for strict parsing and tamper detection. It intentionally
omits encryption and key handling in this phase.

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

## FileHeader (fixed-size)

Length: 36 bytes

| Offset | Size | Field              | Description                             |
|--------|------|--------------------|-----------------------------------------|
| 0      | 8    | magic              | ASCII `AEGIS\0\0\0`                   |
| 8      | 2    | version            | v0 = 0                                  |
| 10     | 2    | header_len         | Must be 36 in v0                        |
| 12     | 4    | flags              | Reserved, must be 0 in v0               |
| 16     | 4    | chunk_count        | Number of chunk table entries           |
| 20     | 8    | chunk_table_offset | Must be 36 in v0                        |
| 28     | 8    | footer_offset      | Byte offset to footer                   |

Rules:

- magic and version validated immediately
- header_len enables future extension but MUST equal 36 in v0
- flags != 0 MUST error in v0

## ChunkTable

Each entry is 24 bytes. Entries MUST be sorted and contiguous by offset.

| Offset | Size | Field      | Description                    |
|--------|------|------------|--------------------------------|
| 0      | 4    | chunk_id   | Logical chunk identifier       |
| 4      | 2    | chunk_type | Enumerated type (see below)    |
| 6      | 2    | flags      | Reserved for future use        |
| 8      | 8    | offset     | Absolute offset to chunk data  |
| 16     | 8    | length     | Chunk length in bytes          |

Chunk types (v0):

- 0x0001 = Data
- 0x0002 = Metadata
- 0xFFFF = Reserved

Rules:

- offsets must point forward, starting immediately after the chunk table
- chunks MUST NOT overlap
- gaps are rejected (no implicit padding)

## ChunkData

Raw bytes with no interpretation in v0. Data is read and written using
streaming I/O and should not be fully loaded into memory by default.

## Footer

| Offset | Size | Field          | Description                         |
|--------|------|----------------|-------------------------------------|
| 0      | 4    | footer_magic   | ASCII `AEGF`                        |
| 4      | 4    | footer_len     | Total footer size in bytes          |
| 8      | 2    | checksum_type  | 0x0001 = CRC32                      |
| 10     | 2    | checksum_len   | Length of checksum bytes            |
| 12     | N    | checksum_bytes | Checksum over bytes before footer   |

Checksum notes:

- CRC32 is used for tamper detection only.
- This is NOT cryptographically secure.
- The checksum covers all bytes from the start of the file up to (but not
  including) the footer.
