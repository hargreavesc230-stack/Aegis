use std::io::{self, Read, Write};

use aegis_core::crypto::aead::DecryptReader;
use aegis_core::crypto::kdf::KdfParams;
use aegis_core::crypto::wrap::unwrap_key;
use aegis_core::io_ext::read_exact_or_err;
use aegis_core::Crc32;

use crate::acf::{
    parse_header, ChecksumType, ChunkEntry, ChunkType, CryptoHeader, FileHeader, FooterV0,
    FooterV1, FormatError, WrapType, ACF_VERSION_V0, ACF_VERSION_V1, ACF_VERSION_V2, CHUNK_LEN,
    FOOTER_MAGIC, FOOTER_V1_LEN, HEADER_BASE_LEN, MAX_HEADER_LEN,
};
use crate::validate::{validate_chunks, validate_header};

#[derive(Debug, Clone)]
pub struct ParsedContainer {
    pub header: FileHeader,
    pub chunks: Vec<ChunkEntry>,
    pub footer: FooterV0,
    pub checksum_valid: bool,
    pub computed_checksum: u32,
}

#[derive(Debug, Clone)]
pub struct DecryptedContainer {
    pub header: FileHeader,
    pub chunks: Vec<ChunkEntry>,
    pub footer: FooterV1,
}

pub fn read_header<R: Read>(reader: &mut R) -> Result<(FileHeader, Vec<u8>), FormatError> {
    let mut base = [0u8; HEADER_BASE_LEN];
    read_exact_truncated(reader, &mut base)?;

    let header_len = u16::from_le_bytes([base[10], base[11]]) as usize;
    if header_len < HEADER_BASE_LEN {
        return Err(FormatError::InvalidHeaderLength {
            found: header_len as u16,
            expected: HEADER_BASE_LEN as u16,
        });
    }
    if header_len > MAX_HEADER_LEN {
        return Err(FormatError::HeaderTooLarge(header_len));
    }

    let mut header_bytes = Vec::with_capacity(header_len);
    header_bytes.extend_from_slice(&base);

    if header_len > HEADER_BASE_LEN {
        let remaining = header_len - HEADER_BASE_LEN;
        let mut extra = vec![0u8; remaining];
        read_exact_truncated(reader, &mut extra)?;
        header_bytes.extend_from_slice(&extra);
    }

    let header = parse_header(&header_bytes)?;
    Ok((header, header_bytes))
}

pub fn read_container<R: Read>(reader: &mut R) -> Result<ParsedContainer, FormatError> {
    read_container_internal(reader, None, true)
}

pub fn read_container_with_status<R: Read>(reader: &mut R) -> Result<ParsedContainer, FormatError> {
    read_container_internal(reader, None, false)
}

pub fn extract_data_chunk<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<ParsedContainer, FormatError> {
    read_container_internal(reader, Some(writer), true)
}

pub fn decrypt_container<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_material: &[u8],
) -> Result<DecryptedContainer, FormatError> {
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V1 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let (salt, nonce) = match header
        .crypto
        .as_ref()
        .ok_or(FormatError::MissingCryptoHeader)?
    {
        CryptoHeader::V1 { salt, nonce, .. } => (salt, nonce),
        _ => return Err(FormatError::MissingCryptoHeader),
    };

    let derived = aegis_core::crypto::kdf::derive_key(key_material, salt, KdfParams::default())?;

    let mut decrypt_reader = DecryptReader::new(reader, derived.as_slice(), nonce, &header_bytes)?;

    let mut chunks = Vec::with_capacity(header.chunk_count as usize);
    for _ in 0..header.chunk_count {
        let mut entry_buf = [0u8; CHUNK_LEN];
        read_exact_plaintext(&mut decrypt_reader, &mut entry_buf)?;

        let chunk_id = u32::from_le_bytes([entry_buf[0], entry_buf[1], entry_buf[2], entry_buf[3]]);
        let chunk_type_raw = u16::from_le_bytes([entry_buf[4], entry_buf[5]]);
        let flags = u16::from_le_bytes([entry_buf[6], entry_buf[7]]);
        let offset = u64::from_le_bytes([
            entry_buf[8],
            entry_buf[9],
            entry_buf[10],
            entry_buf[11],
            entry_buf[12],
            entry_buf[13],
            entry_buf[14],
            entry_buf[15],
        ]);
        let length = u64::from_le_bytes([
            entry_buf[16],
            entry_buf[17],
            entry_buf[18],
            entry_buf[19],
            entry_buf[20],
            entry_buf[21],
            entry_buf[22],
            entry_buf[23],
        ]);

        let chunk_type = ChunkType::try_from(chunk_type_raw)?;

        chunks.push(ChunkEntry {
            chunk_id,
            chunk_type,
            flags,
            offset,
            length,
        });
    }

    let _data_start = validate_chunks(&header, &chunks)?;

    let mut data_chunk_seen = false;
    for chunk in &chunks {
        if chunk.chunk_type == ChunkType::Data {
            if data_chunk_seen {
                return Err(FormatError::MultipleDataChunks);
            }
            data_chunk_seen = true;
            if chunk.length > 0 {
                copy_exact_plaintext(&mut decrypt_reader, writer, chunk.length)?;
            }
        } else if chunk.length > 0 {
            skip_exact_plaintext(&mut decrypt_reader, chunk.length)?;
        }
    }

    if !data_chunk_seen {
        return Err(FormatError::MissingDataChunk);
    }

    let footer = read_footer_v1(&mut decrypt_reader)?;
    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(DecryptedContainer {
        header,
        chunks,
        footer,
    })
}

pub fn decrypt_container_v2<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_material: &[u8],
    wrap_type: WrapType,
) -> Result<DecryptedContainer, FormatError> {
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V2 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let (kdf_params, salt, nonce, header_wrap_type, wrapped_key) = match header
        .crypto
        .as_ref()
        .ok_or(FormatError::MissingCryptoHeader)?
    {
        CryptoHeader::V2 {
            kdf_params,
            salt,
            nonce,
            wrap_type,
            wrapped_key,
            ..
        } => (kdf_params, salt, nonce, *wrap_type, wrapped_key),
        _ => return Err(FormatError::MissingCryptoHeader),
    };

    if header_wrap_type != wrap_type {
        return Err(FormatError::WrapTypeMismatch);
    }

    let kdf_params = KdfParams {
        memory_kib: kdf_params.memory_kib,
        iterations: kdf_params.iterations,
        parallelism: kdf_params.parallelism,
        output_len: aegis_core::crypto::aead::AEAD_KEY_LEN,
    };

    let derived = aegis_core::crypto::kdf::derive_key(key_material, salt, kdf_params)?;
    let data_key = unwrap_key(derived.as_slice(), wrapped_key)?;

    let mut decrypt_reader = DecryptReader::new(reader, data_key.as_slice(), nonce, &header_bytes)?;

    let mut chunks = Vec::with_capacity(header.chunk_count as usize);
    for _ in 0..header.chunk_count {
        let mut entry_buf = [0u8; CHUNK_LEN];
        read_exact_plaintext(&mut decrypt_reader, &mut entry_buf)?;

        let chunk_id = u32::from_le_bytes([entry_buf[0], entry_buf[1], entry_buf[2], entry_buf[3]]);
        let chunk_type_raw = u16::from_le_bytes([entry_buf[4], entry_buf[5]]);
        let flags = u16::from_le_bytes([entry_buf[6], entry_buf[7]]);
        let offset = u64::from_le_bytes([
            entry_buf[8],
            entry_buf[9],
            entry_buf[10],
            entry_buf[11],
            entry_buf[12],
            entry_buf[13],
            entry_buf[14],
            entry_buf[15],
        ]);
        let length = u64::from_le_bytes([
            entry_buf[16],
            entry_buf[17],
            entry_buf[18],
            entry_buf[19],
            entry_buf[20],
            entry_buf[21],
            entry_buf[22],
            entry_buf[23],
        ]);

        let chunk_type = ChunkType::try_from(chunk_type_raw)?;

        chunks.push(ChunkEntry {
            chunk_id,
            chunk_type,
            flags,
            offset,
            length,
        });
    }

    let _data_start = validate_chunks(&header, &chunks)?;

    let mut data_chunk_seen = false;
    for chunk in &chunks {
        if chunk.chunk_type == ChunkType::Data {
            if data_chunk_seen {
                return Err(FormatError::MultipleDataChunks);
            }
            data_chunk_seen = true;
            if chunk.length > 0 {
                copy_exact_plaintext(&mut decrypt_reader, writer, chunk.length)?;
            }
        } else if chunk.length > 0 {
            skip_exact_plaintext(&mut decrypt_reader, chunk.length)?;
        }
    }

    if !data_chunk_seen {
        return Err(FormatError::MissingDataChunk);
    }

    let footer = read_footer_v1(&mut decrypt_reader)?;
    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(DecryptedContainer {
        header,
        chunks,
        footer,
    })
}

fn read_container_internal<R: Read>(
    reader: &mut R,
    mut data_out: Option<&mut dyn Write>,
    strict_checksum: bool,
) -> Result<ParsedContainer, FormatError> {
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V0 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let mut crc = Crc32::new();
    crc.update(&header_bytes);

    let mut chunks = Vec::with_capacity(header.chunk_count as usize);
    for _ in 0..header.chunk_count {
        let mut entry_buf = [0u8; CHUNK_LEN];
        read_exact_update(reader, &mut entry_buf, &mut crc)?;

        let chunk_id = u32::from_le_bytes([entry_buf[0], entry_buf[1], entry_buf[2], entry_buf[3]]);
        let chunk_type_raw = u16::from_le_bytes([entry_buf[4], entry_buf[5]]);
        let flags = u16::from_le_bytes([entry_buf[6], entry_buf[7]]);
        let offset = u64::from_le_bytes([
            entry_buf[8],
            entry_buf[9],
            entry_buf[10],
            entry_buf[11],
            entry_buf[12],
            entry_buf[13],
            entry_buf[14],
            entry_buf[15],
        ]);
        let length = u64::from_le_bytes([
            entry_buf[16],
            entry_buf[17],
            entry_buf[18],
            entry_buf[19],
            entry_buf[20],
            entry_buf[21],
            entry_buf[22],
            entry_buf[23],
        ]);

        let chunk_type = ChunkType::try_from(chunk_type_raw)?;

        chunks.push(ChunkEntry {
            chunk_id,
            chunk_type,
            flags,
            offset,
            length,
        });
    }

    let _data_start = validate_chunks(&header, &chunks)?;

    let mut data_chunk_seen = false;
    for chunk in &chunks {
        if let Some(writer) = data_out.as_mut() {
            let writer: &mut dyn Write = &mut **writer;
            if chunk.chunk_type == ChunkType::Data {
                if data_chunk_seen {
                    return Err(FormatError::MultipleDataChunks);
                }
                data_chunk_seen = true;
                if chunk.length > 0 {
                    copy_exact_update(reader, writer, chunk.length, &mut crc)?;
                }
            } else if chunk.length > 0 {
                skip_exact_update(reader, chunk.length, &mut crc)?;
            }
        } else if chunk.length > 0 {
            skip_exact_update(reader, chunk.length, &mut crc)?;
        }
    }

    if data_out.is_some() && !data_chunk_seen {
        return Err(FormatError::MissingDataChunk);
    }

    let footer = read_footer_v0(reader)?;

    let computed = crc.finalize();
    let checksum_valid = computed == footer.checksum;

    if strict_checksum && !checksum_valid {
        return Err(FormatError::ChecksumMismatch {
            expected: footer.checksum,
            found: computed,
        });
    }

    ensure_eof(reader)?;

    Ok(ParsedContainer {
        header,
        chunks,
        footer,
        checksum_valid,
        computed_checksum: computed,
    })
}

fn read_footer_v0<R: Read>(reader: &mut R) -> Result<FooterV0, FormatError> {
    let mut magic = [0u8; 4];
    read_exact_truncated(reader, &mut magic)?;

    if magic != FOOTER_MAGIC {
        return Err(FormatError::InvalidFooterMagic { found: magic });
    }

    let footer_len = read_u32(reader)?;
    let checksum_type = ChecksumType::try_from(read_u16(reader)?)?;
    let checksum_len = read_u16(reader)?;

    if checksum_len != checksum_type.len() {
        return Err(FormatError::InvalidChecksumLength {
            found: checksum_len,
            expected: checksum_type.len(),
        });
    }

    let expected_footer_len = 4u32 + 4u32 + 2u32 + 2u32 + checksum_len as u32;
    if footer_len != expected_footer_len {
        return Err(FormatError::InvalidFooterLength {
            found: footer_len,
            expected: expected_footer_len,
        });
    }

    let mut checksum_bytes = [0u8; 4];
    read_exact_truncated(reader, &mut checksum_bytes)?;
    let checksum = u32::from_le_bytes(checksum_bytes);

    Ok(FooterV0 {
        footer_len,
        checksum_type,
        checksum,
    })
}

fn read_footer_v1<R: Read>(reader: &mut DecryptReader<R>) -> Result<FooterV1, FormatError> {
    let mut magic = [0u8; 4];
    read_exact_plaintext(reader, &mut magic)?;

    if magic != FOOTER_MAGIC {
        return Err(FormatError::InvalidFooterMagic { found: magic });
    }

    let footer_len = read_u32_plaintext(reader)?;
    let flags = read_u32_plaintext(reader)?;

    if footer_len != FOOTER_V1_LEN {
        return Err(FormatError::InvalidFooterLength {
            found: footer_len,
            expected: FOOTER_V1_LEN,
        });
    }

    Ok(FooterV1 { footer_len, flags })
}

fn read_exact_update<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    crc: &mut Crc32,
) -> Result<(), FormatError> {
    read_exact_truncated(reader, buf)?;
    crc.update(buf);
    Ok(())
}

fn skip_exact_update<R: Read>(
    reader: &mut R,
    mut len: u64,
    crc: &mut Crc32,
) -> Result<(), FormatError> {
    let mut buffer = [0u8; 8192];

    while len > 0 {
        let to_read = std::cmp::min(len, buffer.len() as u64) as usize;
        let read = reader
            .read(&mut buffer[..to_read])
            .map_err(FormatError::Io)?;
        if read == 0 {
            return Err(FormatError::Truncated);
        }
        crc.update(&buffer[..read]);
        len -= read as u64;
    }

    Ok(())
}

fn copy_exact_update<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    mut len: u64,
    crc: &mut Crc32,
) -> Result<(), FormatError> {
    let mut buffer = [0u8; 8192];

    while len > 0 {
        let to_read = std::cmp::min(len, buffer.len() as u64) as usize;
        let read = reader
            .read(&mut buffer[..to_read])
            .map_err(FormatError::Io)?;
        if read == 0 {
            return Err(FormatError::Truncated);
        }
        crc.update(&buffer[..read]);
        writer.write_all(&buffer[..read]).map_err(FormatError::Io)?;
        len -= read as u64;
    }

    Ok(())
}

fn copy_exact_plaintext<R: Read, W: Write>(
    reader: &mut DecryptReader<R>,
    writer: &mut W,
    mut len: u64,
) -> Result<(), FormatError> {
    let mut buffer = [0u8; 8192];

    while len > 0 {
        let to_read = std::cmp::min(len, buffer.len() as u64) as usize;
        let read = reader.read_plaintext(&mut buffer[..to_read])?;
        if read == 0 {
            return Err(FormatError::Truncated);
        }
        writer.write_all(&buffer[..read]).map_err(FormatError::Io)?;
        len -= read as u64;
    }

    Ok(())
}

fn skip_exact_plaintext<R: Read>(
    reader: &mut DecryptReader<R>,
    mut len: u64,
) -> Result<(), FormatError> {
    let mut buffer = [0u8; 8192];

    while len > 0 {
        let to_read = std::cmp::min(len, buffer.len() as u64) as usize;
        let read = reader.read_plaintext(&mut buffer[..to_read])?;
        if read == 0 {
            return Err(FormatError::Truncated);
        }
        len -= read as u64;
    }

    Ok(())
}

fn read_exact_truncated<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), FormatError> {
    match read_exact_or_err(reader, buf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(FormatError::Truncated),
        Err(err) => Err(FormatError::Io(err)),
    }
}

fn read_exact_plaintext<R: Read>(
    reader: &mut DecryptReader<R>,
    buf: &mut [u8],
) -> Result<(), FormatError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let read = reader
            .read_plaintext(&mut buf[offset..])
            .map_err(FormatError::Crypto)?;
        if read == 0 {
            return Err(FormatError::Truncated);
        }
        offset += read;
    }
    Ok(())
}

fn read_u16<R: Read>(reader: &mut R) -> Result<u16, FormatError> {
    let mut buf = [0u8; 2];
    read_exact_truncated(reader, &mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, FormatError> {
    let mut buf = [0u8; 4];
    read_exact_truncated(reader, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u32_plaintext<R: Read>(reader: &mut DecryptReader<R>) -> Result<u32, FormatError> {
    let mut buf = [0u8; 4];
    read_exact_plaintext(reader, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn ensure_eof<R: Read>(reader: &mut R) -> Result<(), FormatError> {
    let mut buf = [0u8; 1];
    match reader.read(&mut buf) {
        Ok(0) => Ok(()),
        Ok(_) => Err(FormatError::TrailingData),
        Err(err) => Err(FormatError::Io(err)),
    }
}

fn ensure_plaintext_eof<R: Read>(reader: &mut DecryptReader<R>) -> Result<(), FormatError> {
    let mut buf = [0u8; 1];
    match reader.read_plaintext(&mut buf) {
        Ok(0) => Ok(()),
        Ok(_) => Err(FormatError::TrailingData),
        Err(err) => Err(FormatError::Crypto(err)),
    }
}
