use std::io;

use aegis_core::crypto::ids::{CipherId, KdfId};
use aegis_core::crypto::CryptoError;
use thiserror::Error;

pub const FILE_MAGIC: [u8; 8] = *b"AEGIS\0\0\0";
pub const FOOTER_MAGIC: [u8; 4] = *b"AEGF";

pub const ACF_VERSION_V0: u16 = 0;
pub const ACF_VERSION_V1: u16 = 1;

pub const HEADER_BASE_LEN: usize = 36;
pub const HEADER_BASE_LEN_U16: u16 = 36;

pub const CHUNK_LEN: usize = 24;
pub const CHUNK_LEN_U16: u16 = 24;

pub const FOOTER_V1_LEN: u32 = 12;
pub const MAX_HEADER_LEN: usize = 4096;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoHeader {
    pub cipher_id: CipherId,
    pub kdf_id: KdfId,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub version: u16,
    pub header_len: u16,
    pub flags: u32,
    pub chunk_count: u32,
    pub chunk_table_offset: u64,
    pub footer_offset: u64,
    pub crypto: Option<CryptoHeader>,
}

impl FileHeader {
    pub fn new_v0(chunk_count: u32, footer_offset: u64) -> Self {
        Self {
            version: ACF_VERSION_V0,
            header_len: HEADER_BASE_LEN_U16,
            flags: 0,
            chunk_count,
            chunk_table_offset: HEADER_BASE_LEN as u64,
            footer_offset,
            crypto: None,
        }
    }

    pub fn new_v1(
        chunk_count: u32,
        footer_offset: u64,
        cipher_id: CipherId,
        kdf_id: KdfId,
        salt: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Self, FormatError> {
        let header_len = header_len_v1(&salt, &nonce)?;
        Ok(Self {
            version: ACF_VERSION_V1,
            header_len,
            flags: 0,
            chunk_count,
            chunk_table_offset: header_len as u64,
            footer_offset,
            crypto: Some(CryptoHeader {
                cipher_id,
                kdf_id,
                salt,
                nonce,
            }),
        })
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
pub struct FooterV0 {
    pub footer_len: u32,
    pub checksum_type: ChecksumType,
    pub checksum: u32,
}

impl FooterV0 {
    pub fn new(checksum_type: ChecksumType, checksum: u32) -> Self {
        let footer_len = 4u32 + 4u32 + 2u32 + 2u32 + checksum_type.len() as u32;
        Self {
            footer_len,
            checksum_type,
            checksum,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FooterV1 {
    pub footer_len: u32,
    pub flags: u32,
}

impl FooterV1 {
    pub fn new() -> Self {
        Self {
            footer_len: FOOTER_V1_LEN,
            flags: 0,
        }
    }
}

impl Default for FooterV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("truncated input")]
    Truncated,
    #[error("invalid magic")]
    InvalidMagic { found: [u8; 8] },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("invalid header length: {found}, expected {expected}")]
    InvalidHeaderLength { found: u16, expected: u16 },
    #[error("header too large: {0}")]
    HeaderTooLarge(usize),
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
    #[error("invalid salt length: {0}")]
    InvalidSaltLength(u16),
    #[error("invalid nonce length: {0}")]
    InvalidNonceLength(u16),
    #[error("missing crypto header")]
    MissingCryptoHeader,
    #[error("checksum mismatch: expected {expected:#010X}, found {found:#010X}")]
    ChecksumMismatch { expected: u32, found: u32 },
    #[error("trailing data after footer")]
    TrailingData,
}

pub fn header_len_v1(salt: &[u8], nonce: &[u8]) -> Result<u16, FormatError> {
    if salt.is_empty() {
        return Err(FormatError::InvalidSaltLength(0));
    }
    if nonce.is_empty() {
        return Err(FormatError::InvalidNonceLength(0));
    }

    let salt_len = u16::try_from(salt.len()).map_err(|_| FormatError::InvalidSaltLength(0))?;
    let nonce_len = u16::try_from(nonce.len()).map_err(|_| FormatError::InvalidNonceLength(0))?;

    let total = HEADER_BASE_LEN + 2 + 2 + 2 + salt_len as usize + 2 + nonce_len as usize;

    if total > MAX_HEADER_LEN {
        return Err(FormatError::HeaderTooLarge(total));
    }

    Ok(total as u16)
}

pub fn encode_header(header: &FileHeader) -> Result<Vec<u8>, FormatError> {
    let expected_len = match header.version {
        ACF_VERSION_V0 => HEADER_BASE_LEN_U16,
        ACF_VERSION_V1 => {
            let crypto = header
                .crypto
                .as_ref()
                .ok_or(FormatError::MissingCryptoHeader)?;
            header_len_v1(&crypto.salt, &crypto.nonce)?
        }
        other => return Err(FormatError::UnsupportedVersion(other)),
    };

    if header.header_len != expected_len {
        return Err(FormatError::InvalidHeaderLength {
            found: header.header_len,
            expected: expected_len,
        });
    }

    let mut buf = Vec::with_capacity(header.header_len as usize);

    buf.extend_from_slice(&FILE_MAGIC);
    buf.extend_from_slice(&header.version.to_le_bytes());
    buf.extend_from_slice(&header.header_len.to_le_bytes());
    buf.extend_from_slice(&header.flags.to_le_bytes());
    buf.extend_from_slice(&header.chunk_count.to_le_bytes());
    buf.extend_from_slice(&header.chunk_table_offset.to_le_bytes());
    buf.extend_from_slice(&header.footer_offset.to_le_bytes());

    if header.version == ACF_VERSION_V1 {
        let crypto = header
            .crypto
            .as_ref()
            .ok_or(FormatError::MissingCryptoHeader)?;
        let cipher_id = crypto.cipher_id as u16;
        let kdf_id = crypto.kdf_id as u16;
        let salt_len =
            u16::try_from(crypto.salt.len()).map_err(|_| FormatError::InvalidSaltLength(0))?;
        let nonce_len =
            u16::try_from(crypto.nonce.len()).map_err(|_| FormatError::InvalidNonceLength(0))?;

        buf.extend_from_slice(&cipher_id.to_le_bytes());
        buf.extend_from_slice(&kdf_id.to_le_bytes());
        buf.extend_from_slice(&salt_len.to_le_bytes());
        buf.extend_from_slice(&crypto.salt);
        buf.extend_from_slice(&nonce_len.to_le_bytes());
        buf.extend_from_slice(&crypto.nonce);
    }

    Ok(buf)
}

pub fn parse_header(buf: &[u8]) -> Result<FileHeader, FormatError> {
    if buf.len() < HEADER_BASE_LEN {
        return Err(FormatError::Truncated);
    }

    let magic = [
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ];
    if magic != FILE_MAGIC {
        return Err(FormatError::InvalidMagic { found: magic });
    }

    let version = u16::from_le_bytes([buf[8], buf[9]]);
    let header_len = u16::from_le_bytes([buf[10], buf[11]]);
    let flags = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let chunk_count = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let chunk_table_offset = u64::from_le_bytes([
        buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
    ]);
    let footer_offset = u64::from_le_bytes([
        buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
    ]);

    let mut crypto = None;

    if version == ACF_VERSION_V0 {
        if header_len != HEADER_BASE_LEN_U16 {
            return Err(FormatError::InvalidHeaderLength {
                found: header_len,
                expected: HEADER_BASE_LEN_U16,
            });
        }
    } else if version == ACF_VERSION_V1 {
        if header_len as usize > MAX_HEADER_LEN {
            return Err(FormatError::HeaderTooLarge(header_len as usize));
        }

        if buf.len() != header_len as usize {
            return Err(FormatError::InvalidHeaderLength {
                found: header_len,
                expected: buf.len() as u16,
            });
        }

        let mut cursor = HEADER_BASE_LEN;
        if buf.len() < cursor + 2 + 2 + 2 + 2 {
            return Err(FormatError::Truncated);
        }

        let cipher_id_raw = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;
        let kdf_id_raw = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;
        let salt_len = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        if salt_len == 0 {
            return Err(FormatError::InvalidSaltLength(0));
        }

        let salt_end = cursor + salt_len as usize;
        if salt_end > buf.len() {
            return Err(FormatError::Truncated);
        }
        let salt = buf[cursor..salt_end].to_vec();
        cursor = salt_end;

        if cursor + 2 > buf.len() {
            return Err(FormatError::Truncated);
        }

        let nonce_len = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;
        if nonce_len == 0 {
            return Err(FormatError::InvalidNonceLength(0));
        }

        let nonce_end = cursor + nonce_len as usize;
        if nonce_end > buf.len() {
            return Err(FormatError::Truncated);
        }
        let nonce = buf[cursor..nonce_end].to_vec();
        cursor = nonce_end;

        if cursor != buf.len() {
            return Err(FormatError::InvalidHeaderLength {
                found: header_len,
                expected: cursor as u16,
            });
        }

        let cipher_id = CipherId::try_from(cipher_id_raw)?;
        let kdf_id = KdfId::try_from(kdf_id_raw)?;

        crypto = Some(CryptoHeader {
            cipher_id,
            kdf_id,
            salt,
            nonce,
        });
    } else {
        return Err(FormatError::UnsupportedVersion(version));
    }

    Ok(FileHeader {
        version,
        header_len,
        flags,
        chunk_count,
        chunk_table_offset,
        footer_offset,
        crypto,
    })
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

pub fn encode_footer_v0(footer: &FooterV0) -> Vec<u8> {
    let mut buf = Vec::with_capacity(footer.footer_len as usize);

    buf.extend_from_slice(&FOOTER_MAGIC);
    buf.extend_from_slice(&footer.footer_len.to_le_bytes());

    let checksum_type = footer.checksum_type as u16;
    buf.extend_from_slice(&checksum_type.to_le_bytes());
    buf.extend_from_slice(&footer.checksum_type.len().to_le_bytes());
    buf.extend_from_slice(&footer.checksum.to_le_bytes());

    buf
}

pub fn encode_footer_v1(footer: &FooterV1) -> Vec<u8> {
    let mut buf = Vec::with_capacity(footer.footer_len as usize);

    buf.extend_from_slice(&FOOTER_MAGIC);
    buf.extend_from_slice(&footer.footer_len.to_le_bytes());
    buf.extend_from_slice(&footer.flags.to_le_bytes());

    buf
}
