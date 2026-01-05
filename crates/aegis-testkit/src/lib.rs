#![deny(warnings)]
#![deny(clippy::all)]

pub const MAGIC: [u8; 4] = *b"AEGS";
pub const HEADER_LEN: u16 = 12;
pub const VERSION_V1: u16 = 1;

pub fn header_bytes(version: u16, flags: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN as usize);

    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&HEADER_LEN.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());

    buf
}

pub fn sample_header_bytes() -> Vec<u8> {
    header_bytes(VERSION_V1, 0)
}

pub fn invalid_magic_bytes() -> Vec<u8> {
    let mut buf = sample_header_bytes();
    buf[0] ^= 0xFF;
    buf
}

pub fn invalid_version_bytes() -> Vec<u8> {
    header_bytes(0xFFFF, 0)
}

pub fn truncated_header_bytes() -> Vec<u8> {
    let mut buf = sample_header_bytes();
    buf.truncate(5);
    buf
}
