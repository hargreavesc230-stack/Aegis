use std::io;

use thiserror::Error;

pub const FILE_MAGIC: [u8; 8] = *b"AEGIS\0\0\0";
pub const FOOTER_MAGIC: [u8; 4] = *b"AEGF";

pub const ACF_VERSION: u16 = 0;

pub const HEADER_LEN: usize = 36;
pub const HEADER_LEN_U16: u16 = 36;

pub const CHUNK_LEN: usize = 24;
pub const CHUNK_LEN_U16: u16 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    Data = 0x0001,
    Metadata = 0x0002,
    Reserved = 0xFFFF,
}

impl TryFrom<u16> for ChunkType {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(ChunkType::Data),
            0x0002 => Ok(ChunkType::Metadata),
            0xFFFF => Ok(ChunkType::Reserved),
            other => Err(FormatError::UnsupportedChunkType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumType {
    Crc32 = 0x0001,
}

impl ChecksumType {
    pub fn len(self) -> u16 {
        match self {
            ChecksumType::Crc32 => 4,
        }
    }

    pub fn is_empty(self) -> bool {
        false
    }
}

impl TryFrom<u16> for ChecksumType {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(ChecksumType::Crc32),
            other => Err(FormatError::UnsupportedChecksumType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub version: u16,
    pub header_len: u16,
    pub flags: u32,
    pub chunk_count: u32,
    pub chunk_table_offset: u64,
    pub footer_offset: u64,
}

impl FileHeader {
    pub fn new(chunk_count: u32, footer_offset: u64) -> Self {
        Self {
            version: ACF_VERSION,
            header_len: HEADER_LEN_U16,
            flags: 0,
            chunk_count,
            chunk_table_offset: HEADER_LEN as u64,
            footer_offset,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkEntry {
    pub chunk_id: u32,
    pub chunk_type: ChunkType,
    pub flags: u16,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footer {
    pub footer_len: u32,
    pub checksum_type: ChecksumType,
    pub checksum: u32,
}

impl Footer {
    pub fn new(checksum_type: ChecksumType, checksum: u32) -> Self {
        let footer_len = 4u32 + 4u32 + 2u32 + 2u32 + checksum_type.len() as u32;
        Self {
            footer_len,
            checksum_type,
            checksum,
        }
    }
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("truncated input")]
    Truncated,
    #[error("invalid magic")]
    InvalidMagic { found: [u8; 8] },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("invalid header length: {found}, expected {expected}")]
    InvalidHeaderLength { found: u16, expected: u16 },
    #[error("unsupported flags: {0}")]
    UnsupportedFlags(u32),
    #[error("invalid chunk table offset: {found}, expected {expected}")]
    InvalidChunkTableOffset { found: u64, expected: u64 },
    #[error("chunk count too large")]
    ChunkCountTooLarge,
    #[error("chunk count mismatch: expected {expected}, found {found}")]
    ChunkCountMismatch { expected: u32, found: u32 },
    #[error("invalid footer offset: {found}, expected {expected}")]
    InvalidFooterOffset { found: u64, expected: u64 },
    #[error("unsupported chunk type: {0}")]
    UnsupportedChunkType(u16),
    #[error("chunk before table: index {index}")]
    ChunkBeforeTable { index: u32 },
    #[error("non-contiguous chunk: index {index}, expected offset {expected}, found {found}")]
    NonContiguousChunk {
        index: u32,
        expected: u64,
        found: u64,
    },
    #[error("overlapping chunk: index {index}")]
    OverlappingChunk { index: u32 },
    #[error("chunk length overflow: index {index}")]
    ChunkLengthOverflow { index: u32 },
    #[error("missing data chunk")]
    MissingDataChunk,
    #[error("multiple data chunks detected")]
    MultipleDataChunks,
    #[error("invalid footer magic")]
    InvalidFooterMagic { found: [u8; 4] },
    #[error("unsupported checksum type: {0}")]
    UnsupportedChecksumType(u16),
    #[error("invalid footer length: {found}, expected {expected}")]
    InvalidFooterLength { found: u32, expected: u32 },
    #[error("invalid checksum length: {found}, expected {expected}")]
    InvalidChecksumLength { found: u16, expected: u16 },
    #[error("checksum mismatch: expected {expected:#010X}, found {found:#010X}")]
    ChecksumMismatch { expected: u32, found: u32 },
    #[error("trailing data after footer")]
    TrailingData,
}

pub fn encode_header(header: &FileHeader) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];

    buf[0..8].copy_from_slice(&FILE_MAGIC);
    buf[8..10].copy_from_slice(&header.version.to_le_bytes());
    buf[10..12].copy_from_slice(&header.header_len.to_le_bytes());
    buf[12..16].copy_from_slice(&header.flags.to_le_bytes());
    buf[16..20].copy_from_slice(&header.chunk_count.to_le_bytes());
    buf[20..28].copy_from_slice(&header.chunk_table_offset.to_le_bytes());
    buf[28..36].copy_from_slice(&header.footer_offset.to_le_bytes());

    buf
}

pub fn encode_chunk_entry(entry: &ChunkEntry) -> [u8; CHUNK_LEN] {
    let mut buf = [0u8; CHUNK_LEN];

    buf[0..4].copy_from_slice(&entry.chunk_id.to_le_bytes());
    let chunk_type = entry.chunk_type as u16;
    buf[4..6].copy_from_slice(&chunk_type.to_le_bytes());
    buf[6..8].copy_from_slice(&entry.flags.to_le_bytes());
    buf[8..16].copy_from_slice(&entry.offset.to_le_bytes());
    buf[16..24].copy_from_slice(&entry.length.to_le_bytes());

    buf
}

pub fn encode_footer(footer: &Footer) -> Vec<u8> {
    let mut buf = Vec::with_capacity(footer.footer_len as usize);

    buf.extend_from_slice(&FOOTER_MAGIC);
    buf.extend_from_slice(&footer.footer_len.to_le_bytes());

    let checksum_type = footer.checksum_type as u16;
    buf.extend_from_slice(&checksum_type.to_le_bytes());
    buf.extend_from_slice(&footer.checksum_type.len().to_le_bytes());
    buf.extend_from_slice(&footer.checksum.to_le_bytes());

    buf
}
