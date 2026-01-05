# Format Overview (Draft)

Aegis uses a compact binary container format designed for streaming I/O. The
current implementation only defines a minimal header for versioning and
future extension. No encryption is implemented yet.

## Header layout (little-endian)

Total length: 12 bytes

| Offset | Size | Field        | Description                     |
|--------|------|--------------|---------------------------------|
| 0      | 4    | Magic        | ASCII `AEGS`                    |
| 4      | 2    | Version      | `1` for the initial draft       |
| 6      | 2    | Header Len   | Must be `12` for this version   |
| 8      | 4    | Flags        | Reserved, must be preserved     |

## Parsing rules

- Reject inputs shorter than 12 bytes.
- Reject magic values that do not match `AEGS`.
- Reject versions that are not explicitly supported.
- Reject header lengths that do not match the expected size.

## Future fields

A later revision will introduce authenticated metadata, key wrapping
information, and payload framing. These are intentionally out of scope for
this scaffolding phase.
