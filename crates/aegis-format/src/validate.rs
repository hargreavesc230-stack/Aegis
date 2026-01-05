use aegis_core::crypto::aead::AEAD_NONCE_LEN;
use aegis_core::crypto::kdf::DEFAULT_SALT_LEN;

use crate::acf::{
    header_len_v1, ChunkEntry, FileHeader, FormatError, ACF_VERSION_V0, ACF_VERSION_V1, CHUNK_LEN,
    HEADER_BASE_LEN_U16,
};

pub fn validate_header(header: &FileHeader) -> Result<(), FormatError> {
    if header.flags != 0 {
        return Err(FormatError::UnsupportedFlags(header.flags));
    }

    match header.version {
        ACF_VERSION_V0 => {
            if header.header_len != HEADER_BASE_LEN_U16 {
                return Err(FormatError::InvalidHeaderLength {
                    found: header.header_len,
                    expected: HEADER_BASE_LEN_U16,
                });
            }
            if header.crypto.is_some() {
                return Err(FormatError::InvalidHeaderLength {
                    found: header.header_len,
                    expected: HEADER_BASE_LEN_U16,
                });
            }
        }
        ACF_VERSION_V1 => {
            let crypto = header
                .crypto
                .as_ref()
                .ok_or(FormatError::MissingCryptoHeader)?;
            let expected_len = header_len_v1(&crypto.salt, &crypto.nonce)?;
            if header.header_len != expected_len {
                return Err(FormatError::InvalidHeaderLength {
                    found: header.header_len,
                    expected: expected_len,
                });
            }
            if crypto.salt.len() != DEFAULT_SALT_LEN {
                return Err(FormatError::InvalidSaltLength(crypto.salt.len() as u16));
            }
            if crypto.nonce.len() != AEAD_NONCE_LEN {
                return Err(FormatError::InvalidNonceLength(crypto.nonce.len() as u16));
            }
        }
        other => return Err(FormatError::UnsupportedVersion(other)),
    }

    let expected_offset = header.header_len as u64;
    if header.chunk_table_offset != expected_offset {
        return Err(FormatError::InvalidChunkTableOffset {
            found: header.chunk_table_offset,
            expected: expected_offset,
        });
    }

    Ok(())
}

pub fn validate_chunks(header: &FileHeader, chunks: &[ChunkEntry]) -> Result<u64, FormatError> {
    let expected_count = header.chunk_count as usize;
    if expected_count != chunks.len() {
        return Err(FormatError::ChunkCountMismatch {
            expected: header.chunk_count,
            found: chunks.len() as u32,
        });
    }

    let table_len = (header.chunk_count as u64)
        .checked_mul(CHUNK_LEN as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;

    let data_start = header
        .chunk_table_offset
        .checked_add(table_len)
        .ok_or(FormatError::ChunkCountTooLarge)?;

    if header.footer_offset < data_start {
        return Err(FormatError::InvalidFooterOffset {
            found: header.footer_offset,
            expected: data_start,
        });
    }

    let mut expected_offset = data_start;

    for (index, chunk) in chunks.iter().enumerate() {
        let idx = index as u32;

        if chunk.offset < data_start {
            return Err(FormatError::ChunkBeforeTable { index: idx });
        }

        if chunk.offset < expected_offset {
            return Err(FormatError::OverlappingChunk { index: idx });
        }

        if chunk.offset > expected_offset {
            return Err(FormatError::NonContiguousChunk {
                index: idx,
                expected: expected_offset,
                found: chunk.offset,
            });
        }

        let next_offset = expected_offset
            .checked_add(chunk.length)
            .ok_or(FormatError::ChunkLengthOverflow { index: idx })?;

        if next_offset > header.footer_offset {
            return Err(FormatError::InvalidFooterOffset {
                found: header.footer_offset,
                expected: next_offset,
            });
        }

        expected_offset = next_offset;
    }

    if expected_offset != header.footer_offset {
        return Err(FormatError::InvalidFooterOffset {
            found: header.footer_offset,
            expected: expected_offset,
        });
    }

    Ok(data_start)
}
