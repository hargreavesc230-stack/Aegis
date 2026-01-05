#![deny(warnings)]
#![deny(clippy::all)]

use std::io::{self, Read, Write};

use aegis_core::util::ct_eq;
use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"AEGS";
pub const HEADER_LEN: usize = 12;
pub const VERSION_OFFSET: usize = 4;
pub const HEADER_LEN_OFFSET: usize = 6;
pub const FLAGS_OFFSET: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1 = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerHeader {
    pub version: Version,
    pub flags: u32,
}

impl ContainerHeader {
    pub fn new(version: Version) -> Self {
        Self { version, flags: 0 }
    }
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("truncated input")]
    Truncated,
    #[error("invalid magic")]
    InvalidMagic { found: [u8; 4] },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported header length: {found}, expected {expected}")]
    UnsupportedHeaderLength { found: u16, expected: u16 },
}

impl TryFrom<u16> for Version {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::V1),
            other => Err(FormatError::UnsupportedVersion(other)),
        }
    }
}

pub fn read_header<R: Read>(reader: &mut R) -> Result<ContainerHeader, FormatError> {
    let mut buf = [0u8; HEADER_LEN];

    match reader.read_exact(&mut buf) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(FormatError::Truncated)
        }
        Err(err) => return Err(FormatError::Io(err)),
    }

    let magic = [buf[0], buf[1], buf[2], buf[3]];
    if !ct_eq(&magic, &MAGIC) {
        return Err(FormatError::InvalidMagic { found: magic });
    }

    let version_raw = u16::from_le_bytes([buf[VERSION_OFFSET], buf[VERSION_OFFSET + 1]]);
    let header_len = u16::from_le_bytes([buf[HEADER_LEN_OFFSET], buf[HEADER_LEN_OFFSET + 1]]);

    if header_len as usize != HEADER_LEN {
        return Err(FormatError::UnsupportedHeaderLength {
            found: header_len,
            expected: HEADER_LEN as u16,
        });
    }

    let flags = u32::from_le_bytes([
        buf[FLAGS_OFFSET],
        buf[FLAGS_OFFSET + 1],
        buf[FLAGS_OFFSET + 2],
        buf[FLAGS_OFFSET + 3],
    ]);

    let version = Version::try_from(version_raw)?;

    Ok(ContainerHeader { version, flags })
}

pub fn write_header<W: Write>(writer: &mut W, header: &ContainerHeader) -> Result<(), FormatError> {
    let mut buf = [0u8; HEADER_LEN];

    buf[0..4].copy_from_slice(&MAGIC);

    let version = header.version as u16;
    buf[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&version.to_le_bytes());

    let header_len = HEADER_LEN as u16;
    buf[HEADER_LEN_OFFSET..HEADER_LEN_OFFSET + 2].copy_from_slice(&header_len.to_le_bytes());

    buf[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&header.flags.to_le_bytes());

    writer.write_all(&buf).map_err(FormatError::Io)
}
