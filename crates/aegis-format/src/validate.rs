use aegis_core::crypto::aead::{AEAD_NONCE_LEN, AEAD_TAG_LEN};
use aegis_core::crypto::kdf::{
    DEFAULT_KEYFILE_PARAMS, DEFAULT_PASSWORD_PARAMS, DEFAULT_SALT_LEN, KDF_ITERATIONS_MAX,
    KDF_ITERATIONS_MIN, KDF_MEMORY_KIB_MAX, KDF_MEMORY_KIB_MIN, KDF_PARALLELISM_MAX,
    KDF_PARALLELISM_MIN,
};
use aegis_core::crypto::wrap::WRAP_NONCE_LEN;

use crate::acf::{
    header_len_v1, header_len_v2, ChunkEntry, CryptoHeader, FileHeader, FormatError, WrapType,
    ACF_VERSION_V0, ACF_VERSION_V1, ACF_VERSION_V2, CHUNK_LEN, HEADER_BASE_LEN_U16,
    MAX_CHUNK_COUNT, MAX_WRAPPED_KEY_LEN,
};

pub fn validate_header(header: &FileHeader) -> Result<(), FormatError> {
    if header.flags != 0 {
        return Err(FormatError::UnsupportedFlags(header.flags));
    }

    if header.chunk_count > MAX_CHUNK_COUNT {
        return Err(FormatError::ChunkCountTooLarge);
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
            let (salt, nonce) = match crypto {
                CryptoHeader::V1 { salt, nonce, .. } => (salt, nonce),
                _ => return Err(FormatError::MissingCryptoHeader),
            };
            let expected_len = header_len_v1(salt, nonce)?;
            if header.header_len != expected_len {
                return Err(FormatError::InvalidHeaderLength {
                    found: header.header_len,
                    expected: expected_len,
                });
            }
            if salt.len() != DEFAULT_SALT_LEN {
                return Err(FormatError::InvalidSaltLength(salt.len() as u16));
            }
            if nonce.len() != AEAD_NONCE_LEN {
                return Err(FormatError::InvalidNonceLength(nonce.len() as u16));
            }
        }
        ACF_VERSION_V2 => {
            let crypto = header
                .crypto
                .as_ref()
                .ok_or(FormatError::MissingCryptoHeader)?;
            let (kdf_params, salt, nonce, wrap_type, wrapped_key) = match crypto {
                CryptoHeader::V2 {
                    kdf_params,
                    salt,
                    nonce,
                    wrap_type,
                    wrapped_key,
                    ..
                } => (kdf_params, salt, nonce, wrap_type, wrapped_key),
                _ => return Err(FormatError::MissingCryptoHeader),
            };
            let expected_len = header_len_v2(salt, nonce, wrapped_key)?;
            if header.header_len != expected_len {
                return Err(FormatError::InvalidHeaderLength {
                    found: header.header_len,
                    expected: expected_len,
                });
            }
            if salt.len() != DEFAULT_SALT_LEN {
                return Err(FormatError::InvalidSaltLength(salt.len() as u16));
            }
            if nonce.len() != AEAD_NONCE_LEN {
                return Err(FormatError::InvalidNonceLength(nonce.len() as u16));
            }
            if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_LEN {
                return Err(FormatError::InvalidWrappedKeyLength(
                    wrapped_key.len() as u16
                ));
            }
            let min_wrapped = 2 + WRAP_NONCE_LEN + AEAD_TAG_LEN;
            if wrapped_key.len() < min_wrapped {
                return Err(FormatError::InvalidWrappedKeyLength(
                    wrapped_key.len() as u16
                ));
            }
            validate_kdf_params(kdf_params)?;
            match wrap_type {
                WrapType::Keyfile => enforce_kdf_minimums(kdf_params, DEFAULT_KEYFILE_PARAMS)?,
                WrapType::Password => enforce_kdf_minimums(kdf_params, DEFAULT_PASSWORD_PARAMS)?,
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

fn validate_kdf_params(params: &crate::acf::KdfParamsHeader) -> Result<(), FormatError> {
    if params.memory_kib < KDF_MEMORY_KIB_MIN || params.memory_kib > KDF_MEMORY_KIB_MAX {
        return Err(FormatError::InvalidKdfMemory(params.memory_kib));
    }
    if params.iterations < KDF_ITERATIONS_MIN || params.iterations > KDF_ITERATIONS_MAX {
        return Err(FormatError::InvalidKdfIterations(params.iterations));
    }
    if params.parallelism < KDF_PARALLELISM_MIN || params.parallelism > KDF_PARALLELISM_MAX {
        return Err(FormatError::InvalidKdfParallelism(params.parallelism));
    }
    Ok(())
}

fn enforce_kdf_minimums(
    params: &crate::acf::KdfParamsHeader,
    minimums: aegis_core::crypto::kdf::KdfParams,
) -> Result<(), FormatError> {
    if params.memory_kib < minimums.memory_kib {
        return Err(FormatError::InvalidKdfMemory(params.memory_kib));
    }
    if params.iterations < minimums.iterations {
        return Err(FormatError::InvalidKdfIterations(params.iterations));
    }
    if params.parallelism < minimums.parallelism {
        return Err(FormatError::InvalidKdfParallelism(params.parallelism));
    }
    Ok(())
}
