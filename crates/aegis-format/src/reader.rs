use std::io::{self, Read, Write};

use aegis_core::crypto::aead::{encrypt_stream, DecryptReader};
use aegis_core::crypto::kdf::KdfParams;
use aegis_core::crypto::public_key::{
    derive_wrapping_key, generate_keypair, public_key_from_private, X25519_KEY_LEN,
};
use aegis_core::crypto::wrap::{unwrap_key, unwrap_key_with_aad, wrap_key_with_aad};
use aegis_core::io_ext::read_exact_or_err;
use aegis_core::Crc32;
use zeroize::Zeroizing;

use crate::acf::{
    encode_chunk_entry, encode_header, parse_header, recipient_aad, recipient_aad_v4, ChecksumType,
    ChunkEntry, ChunkType, CryptoHeader, FileHeader, FooterV0, FooterV1, FormatError,
    RecipientEntry, V3HeaderParams, V4HeaderParams, WrapType, ACF_VERSION_V0, ACF_VERSION_V1,
    ACF_VERSION_V2, ACF_VERSION_V3, ACF_VERSION_V4, CHUNK_LEN, FOOTER_MAGIC, FOOTER_V1_LEN,
    HEADER_BASE_LEN, MAX_HEADER_LEN,
};
use crate::validate::{validate_chunks, validate_header};
use crate::writer::{RecipientSpec, WrittenEncryptedContainer};

// 64 KiB buffers improve streaming throughput while keeping memory bounded.
const IO_BUFFER_SIZE: usize = 64 * 1024;

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

    let mut header_bytes = vec![0u8; header_len];
    header_bytes[..HEADER_BASE_LEN].copy_from_slice(&base);

    if header_len > HEADER_BASE_LEN {
        read_exact_truncated(reader, &mut header_bytes[HEADER_BASE_LEN..])?;
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
    decrypt_container_v1_with_outputs(reader, Some(writer), None, key_material)
}

pub fn decrypt_container_v1_with_outputs<R: Read>(
    reader: &mut R,
    data_out: Option<&mut dyn Write>,
    metadata_out: Option<&mut dyn Write>,
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

    let chunks = read_chunk_entries_plaintext(&mut decrypt_reader, &header)?;
    let _data_start = validate_chunks(&header, &chunks)?;

    extract_chunks_plaintext(&mut decrypt_reader, &chunks, data_out, metadata_out)?;

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
    decrypt_container_v2_with_outputs(reader, Some(writer), None, key_material, wrap_type)
}

pub fn decrypt_container_v2_with_outputs<R: Read>(
    reader: &mut R,
    data_out: Option<&mut dyn Write>,
    metadata_out: Option<&mut dyn Write>,
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

    let chunks = read_chunk_entries_plaintext(&mut decrypt_reader, &header)?;
    let _data_start = validate_chunks(&header, &chunks)?;

    extract_chunks_plaintext(&mut decrypt_reader, &chunks, data_out, metadata_out)?;

    let footer = read_footer_v1(&mut decrypt_reader)?;
    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(DecryptedContainer {
        header,
        chunks,
        footer,
    })
}

pub fn decrypt_container_v3<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_material: &[u8],
    recipient_type: WrapType,
) -> Result<DecryptedContainer, FormatError> {
    decrypt_container_v3_with_outputs(reader, Some(writer), None, key_material, recipient_type)
}

pub fn decrypt_container_v3_with_outputs<R: Read>(
    reader: &mut R,
    data_out: Option<&mut dyn Write>,
    metadata_out: Option<&mut dyn Write>,
    key_material: &[u8],
    recipient_type: WrapType,
) -> Result<DecryptedContainer, FormatError> {
    if recipient_type == WrapType::PublicKey {
        return Err(FormatError::UnsupportedWrapType(WrapType::PublicKey as u16));
    }
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V3 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let (kdf_params, salt, nonce, recipients) = match header
        .crypto
        .as_ref()
        .ok_or(FormatError::MissingCryptoHeader)?
    {
        CryptoHeader::V3 {
            kdf_params,
            salt,
            nonce,
            recipients,
            ..
        } => (kdf_params, salt, nonce, recipients),
        _ => return Err(FormatError::MissingCryptoHeader),
    };

    let kdf_params = KdfParams {
        memory_kib: kdf_params.memory_kib,
        iterations: kdf_params.iterations,
        parallelism: kdf_params.parallelism,
        output_len: aegis_core::crypto::aead::AEAD_KEY_LEN,
    };

    let data_key = select_data_key_v3(recipients, key_material, recipient_type, kdf_params, salt)?;

    let mut decrypt_reader = DecryptReader::new(reader, data_key.as_slice(), nonce, &header_bytes)?;

    let chunks = read_chunk_entries_plaintext(&mut decrypt_reader, &header)?;
    let _data_start = validate_chunks(&header, &chunks)?;

    extract_chunks_plaintext(&mut decrypt_reader, &chunks, data_out, metadata_out)?;

    let footer = read_footer_v1(&mut decrypt_reader)?;
    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(DecryptedContainer {
        header,
        chunks,
        footer,
    })
}

pub fn decrypt_container_v4<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_material: &[u8],
    recipient_type: WrapType,
) -> Result<DecryptedContainer, FormatError> {
    decrypt_container_v4_with_outputs(reader, Some(writer), None, key_material, recipient_type)
}

pub fn decrypt_container_v4_with_outputs<R: Read>(
    reader: &mut R,
    data_out: Option<&mut dyn Write>,
    metadata_out: Option<&mut dyn Write>,
    key_material: &[u8],
    recipient_type: WrapType,
) -> Result<DecryptedContainer, FormatError> {
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V4 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let (kdf_params, salt, nonce, recipients) = match header
        .crypto
        .as_ref()
        .ok_or(FormatError::MissingCryptoHeader)?
    {
        CryptoHeader::V4 {
            kdf_params,
            salt,
            nonce,
            recipients,
            ..
        } => (kdf_params, salt, nonce, recipients),
        _ => return Err(FormatError::MissingCryptoHeader),
    };

    let kdf_params = KdfParams {
        memory_kib: kdf_params.memory_kib,
        iterations: kdf_params.iterations,
        parallelism: kdf_params.parallelism,
        output_len: aegis_core::crypto::aead::AEAD_KEY_LEN,
    };

    let data_key = select_data_key_v4(recipients, key_material, recipient_type, kdf_params, salt)?;

    let mut decrypt_reader = DecryptReader::new(reader, data_key.as_slice(), nonce, &header_bytes)?;

    let chunks = read_chunk_entries_plaintext(&mut decrypt_reader, &header)?;
    let _data_start = validate_chunks(&header, &chunks)?;

    extract_chunks_plaintext(&mut decrypt_reader, &chunks, data_out, metadata_out)?;

    let footer = read_footer_v1(&mut decrypt_reader)?;
    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(DecryptedContainer {
        header,
        chunks,
        footer,
    })
}

fn read_chunk_entries_plaintext<R: Read>(
    reader: &mut DecryptReader<R>,
    header: &FileHeader,
) -> Result<Vec<ChunkEntry>, FormatError> {
    let mut chunks = Vec::with_capacity(header.chunk_count as usize);
    for _ in 0..header.chunk_count {
        let mut entry_buf = [0u8; CHUNK_LEN];
        read_exact_plaintext(reader, &mut entry_buf)?;

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

    Ok(chunks)
}

fn extract_chunks_plaintext<R: Read>(
    reader: &mut DecryptReader<R>,
    chunks: &[ChunkEntry],
    mut data_out: Option<&mut dyn Write>,
    mut metadata_out: Option<&mut dyn Write>,
) -> Result<(), FormatError> {
    let mut data_chunk_seen = false;
    let mut metadata_chunk_seen = false;

    for chunk in chunks {
        match chunk.chunk_type {
            ChunkType::Data => {
                if data_chunk_seen {
                    return Err(FormatError::MultipleDataChunks);
                }
                data_chunk_seen = true;
                if chunk.length > 0 {
                    if let Some(writer) = data_out.as_deref_mut() {
                        copy_exact_plaintext(reader, writer, chunk.length)?;
                    } else {
                        skip_exact_plaintext(reader, chunk.length)?;
                    }
                }
            }
            ChunkType::Metadata => {
                if metadata_out.is_some() {
                    if metadata_chunk_seen {
                        return Err(FormatError::MultipleMetadataChunks);
                    }
                    metadata_chunk_seen = true;
                }
                if chunk.length > 0 {
                    if let Some(writer) = metadata_out.as_deref_mut() {
                        copy_exact_plaintext(reader, writer, chunk.length)?;
                    } else {
                        skip_exact_plaintext(reader, chunk.length)?;
                    }
                }
            }
            _ => {
                if chunk.length > 0 {
                    skip_exact_plaintext(reader, chunk.length)?;
                }
            }
        }
    }

    if !data_chunk_seen {
        return Err(FormatError::MissingDataChunk);
    }

    if metadata_out.is_some() && !metadata_chunk_seen {
        return Err(FormatError::MissingMetadataChunk);
    }

    Ok(())
}

pub fn rotate_container_v3<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_material: &[u8],
    recipient_type: WrapType,
    add_recipients: &[RecipientSpec<'_>],
    remove_ids: &[u32],
) -> Result<WrittenEncryptedContainer, FormatError> {
    if recipient_type == WrapType::PublicKey {
        return Err(FormatError::UnsupportedWrapType(WrapType::PublicKey as u16));
    }
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V3 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let (kdf_params, salt, nonce, existing_recipients) = match header
        .crypto
        .as_ref()
        .ok_or(FormatError::MissingCryptoHeader)?
    {
        CryptoHeader::V3 {
            kdf_params,
            salt,
            nonce,
            recipients,
            ..
        } => (kdf_params, salt, nonce, recipients),
        _ => return Err(FormatError::MissingCryptoHeader),
    };

    let kdf_params = KdfParams {
        memory_kib: kdf_params.memory_kib,
        iterations: kdf_params.iterations,
        parallelism: kdf_params.parallelism,
        output_len: aegis_core::crypto::aead::AEAD_KEY_LEN,
    };

    let data_key = select_data_key_v3(
        existing_recipients,
        key_material,
        recipient_type,
        kdf_params,
        salt,
    )?;

    let mut new_recipients = existing_recipients.clone();
    let existing_ids: std::collections::HashSet<u32> = new_recipients
        .iter()
        .map(|recipient| recipient.recipient_id)
        .collect();
    let remove_set: std::collections::HashSet<u32> = remove_ids.iter().copied().collect();
    for remove_id in &remove_set {
        if !existing_ids.contains(remove_id) {
            return Err(FormatError::RecipientIdNotFound(*remove_id));
        }
    }
    if !remove_set.is_empty() {
        new_recipients.retain(|recipient| !remove_set.contains(&recipient.recipient_id));
    }

    let mut id_set: std::collections::HashSet<u32> =
        new_recipients.iter().map(|r| r.recipient_id).collect();
    for recipient in add_recipients {
        if recipient.recipient_type == WrapType::PublicKey || recipient.public_key.is_some() {
            return Err(FormatError::UnsupportedWrapType(WrapType::PublicKey as u16));
        }
        if !id_set.insert(recipient.recipient_id) {
            return Err(FormatError::DuplicateRecipientId(recipient.recipient_id));
        }

        let key_material = recipient
            .key_material
            .ok_or(FormatError::MissingRecipientKeyMaterial)?;
        let derived = aegis_core::crypto::kdf::derive_key(key_material, salt, kdf_params)?;
        let wrap_alg = crate::acf::WrapAlg::XChaCha20Poly1305;
        let aad = recipient_aad(recipient.recipient_id, recipient.recipient_type, wrap_alg);
        let wrapped_key = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
        new_recipients.push(RecipientEntry {
            recipient_id: recipient.recipient_id,
            recipient_type: recipient.recipient_type,
            wrap_alg,
            wrapped_key,
            recipient_pubkey: None,
            ephemeral_pubkey: None,
        });
    }

    if new_recipients.is_empty() {
        return Err(FormatError::MissingRecipients);
    }

    let mut decrypt_reader = DecryptReader::new(reader, data_key.as_slice(), nonce, &header_bytes)?;

    let table_len = (header.chunk_count as usize)
        .checked_mul(CHUNK_LEN)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let mut table_bytes = vec![0u8; table_len];
    read_exact_plaintext(&mut decrypt_reader, &mut table_bytes)?;

    let mut chunks = Vec::with_capacity(header.chunk_count as usize);
    for entry in table_bytes.chunks_exact(CHUNK_LEN) {
        let chunk_id = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let chunk_type_raw = u16::from_le_bytes([entry[4], entry[5]]);
        let flags = u16::from_le_bytes([entry[6], entry[7]]);
        let offset = u64::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14], entry[15],
        ]);
        let length = u64::from_le_bytes([
            entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22], entry[23],
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

    validate_chunks(&header, &chunks)?;

    let mut new_entries = Vec::with_capacity(chunks.len());
    let new_header_len = crate::acf::header_len_v3(salt, nonce, &new_recipients)? as u64;
    let new_data_start = new_header_len
        .checked_add(table_len as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let mut offset = new_data_start;
    for (index, chunk) in chunks.iter().enumerate() {
        let next_offset =
            offset
                .checked_add(chunk.length)
                .ok_or(FormatError::ChunkLengthOverflow {
                    index: index as u32,
                })?;
        new_entries.push(ChunkEntry {
            chunk_id: chunk.chunk_id,
            chunk_type: chunk.chunk_type,
            flags: chunk.flags,
            offset,
            length: chunk.length,
        });
        offset = next_offset;
    }

    let footer_offset = offset;
    let new_header = FileHeader::new_v3(
        header.chunk_count,
        footer_offset,
        V3HeaderParams {
            cipher_id: header
                .crypto
                .as_ref()
                .and_then(|crypto| match crypto {
                    CryptoHeader::V3 { cipher_id, .. } => Some(*cipher_id),
                    _ => None,
                })
                .ok_or(FormatError::MissingCryptoHeader)?,
            kdf_id: header
                .crypto
                .as_ref()
                .and_then(|crypto| match crypto {
                    CryptoHeader::V3 { kdf_id, .. } => Some(*kdf_id),
                    _ => None,
                })
                .ok_or(FormatError::MissingCryptoHeader)?,
            kdf_params: crate::acf::KdfParamsHeader {
                memory_kib: kdf_params.memory_kib,
                iterations: kdf_params.iterations,
                parallelism: kdf_params.parallelism,
            },
            salt: salt.clone(),
            nonce: nonce.clone(),
            recipients: new_recipients,
        },
    )?;

    validate_header(&new_header)?;
    validate_chunks(&new_header, &new_entries)?;

    let header_bytes = encode_header(&new_header)?;
    writer.write_all(&header_bytes)?;

    let mut new_table_bytes = Vec::with_capacity(new_entries.len() * CHUNK_LEN);
    for entry in &new_entries {
        new_table_bytes.extend_from_slice(&encode_chunk_entry(entry));
    }

    let total_data_len: u64 = chunks.iter().map(|chunk| chunk.length).sum();
    let mut payload = RotatePayloadReader::new(
        &new_table_bytes,
        &mut decrypt_reader,
        total_data_len,
        FOOTER_V1_LEN as usize,
    );

    encrypt_stream(
        &mut payload,
        writer,
        data_key.as_slice(),
        nonce,
        &header_bytes,
    )?;

    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(WrittenEncryptedContainer {
        header: new_header,
        chunks: new_entries,
        footer: FooterV1::new(),
    })
}

pub fn rotate_container_v4<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key_material: &[u8],
    recipient_type: WrapType,
    add_recipients: &[RecipientSpec<'_>],
    remove_ids: &[u32],
) -> Result<WrittenEncryptedContainer, FormatError> {
    let (header, header_bytes) = read_header(reader)?;
    if header.version != ACF_VERSION_V4 {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    validate_header(&header)?;

    let (kdf_params, salt, nonce, existing_recipients) = match header
        .crypto
        .as_ref()
        .ok_or(FormatError::MissingCryptoHeader)?
    {
        CryptoHeader::V4 {
            kdf_params,
            salt,
            nonce,
            recipients,
            ..
        } => (kdf_params, salt, nonce, recipients),
        _ => return Err(FormatError::MissingCryptoHeader),
    };

    let kdf_params = KdfParams {
        memory_kib: kdf_params.memory_kib,
        iterations: kdf_params.iterations,
        parallelism: kdf_params.parallelism,
        output_len: aegis_core::crypto::aead::AEAD_KEY_LEN,
    };

    let data_key = select_data_key_v4(
        existing_recipients,
        key_material,
        recipient_type,
        kdf_params,
        salt,
    )?;

    let existing_ids: std::collections::HashSet<u32> = existing_recipients
        .iter()
        .map(|recipient| recipient.recipient_id)
        .collect();
    let remove_set: std::collections::HashSet<u32> = remove_ids.iter().copied().collect();
    for remove_id in &remove_set {
        if !existing_ids.contains(remove_id) {
            return Err(FormatError::RecipientIdNotFound(*remove_id));
        }
    }

    let mut id_set: std::collections::HashSet<u32> = existing_ids
        .iter()
        .copied()
        .filter(|id| !remove_set.contains(id))
        .collect();

    let mut will_have_public = existing_recipients
        .iter()
        .any(|recipient| recipient.recipient_type == WrapType::PublicKey);
    if add_recipients
        .iter()
        .any(|recipient| recipient.recipient_type == WrapType::PublicKey)
    {
        will_have_public = true;
    }

    let mut ephemeral_private = None;
    let mut ephemeral_public = None;
    if will_have_public {
        let (private, public) = generate_keypair()?;
        // The ephemeral private key is zeroized when it goes out of scope.
        ephemeral_private = Some(private);
        ephemeral_public = Some(public);
    }

    let mut new_recipients = Vec::with_capacity(
        existing_recipients
            .len()
            .saturating_add(add_recipients.len()),
    );
    for recipient in existing_recipients {
        if remove_set.contains(&recipient.recipient_id) {
            continue;
        }

        if recipient.recipient_type == WrapType::PublicKey {
            let recipient_pubkey = *recipient
                .recipient_pubkey
                .as_ref()
                .ok_or(FormatError::MissingRecipientPublicKey)?;
            let private_key = ephemeral_private
                .as_ref()
                .ok_or(FormatError::MissingRecipientEphemeralKey)?;
            let ephemeral_pub = *ephemeral_public
                .as_ref()
                .ok_or(FormatError::MissingRecipientEphemeralKey)?;
            let derived = derive_wrapping_key(private_key, &recipient_pubkey)?;
            let aad = recipient_aad_v4(
                recipient.recipient_id,
                recipient.recipient_type,
                recipient.wrap_alg,
                Some(&recipient_pubkey),
                Some(&ephemeral_pub),
            );
            let wrapped_key = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
            new_recipients.push(RecipientEntry {
                recipient_id: recipient.recipient_id,
                recipient_type: recipient.recipient_type,
                wrap_alg: recipient.wrap_alg,
                wrapped_key,
                recipient_pubkey: Some(recipient_pubkey),
                ephemeral_pubkey: Some(ephemeral_pub),
            });
        } else {
            new_recipients.push(recipient.clone());
        }
    }

    for recipient in add_recipients {
        if !id_set.insert(recipient.recipient_id) {
            return Err(FormatError::DuplicateRecipientId(recipient.recipient_id));
        }

        let wrap_alg = crate::acf::WrapAlg::XChaCha20Poly1305;
        match recipient.recipient_type {
            WrapType::Keyfile | WrapType::Password => {
                let key_material = recipient
                    .key_material
                    .ok_or(FormatError::MissingRecipientKeyMaterial)?;
                let derived = aegis_core::crypto::kdf::derive_key(key_material, salt, kdf_params)?;
                let aad = recipient_aad_v4(
                    recipient.recipient_id,
                    recipient.recipient_type,
                    wrap_alg,
                    None,
                    None,
                );
                let wrapped_key = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
                new_recipients.push(RecipientEntry {
                    recipient_id: recipient.recipient_id,
                    recipient_type: recipient.recipient_type,
                    wrap_alg,
                    wrapped_key,
                    recipient_pubkey: None,
                    ephemeral_pubkey: None,
                });
            }
            WrapType::PublicKey => {
                let public_key = recipient
                    .public_key
                    .ok_or(FormatError::MissingRecipientPublicKey)?;
                let private_key = ephemeral_private
                    .as_ref()
                    .ok_or(FormatError::MissingRecipientEphemeralKey)?;
                let ephemeral_pub = *ephemeral_public
                    .as_ref()
                    .ok_or(FormatError::MissingRecipientEphemeralKey)?;
                let derived = derive_wrapping_key(private_key, &public_key)?;
                let aad = recipient_aad_v4(
                    recipient.recipient_id,
                    recipient.recipient_type,
                    wrap_alg,
                    Some(&public_key),
                    Some(&ephemeral_pub),
                );
                let wrapped_key = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
                new_recipients.push(RecipientEntry {
                    recipient_id: recipient.recipient_id,
                    recipient_type: recipient.recipient_type,
                    wrap_alg,
                    wrapped_key,
                    recipient_pubkey: Some(public_key),
                    ephemeral_pubkey: Some(ephemeral_pub),
                });
            }
        }
    }

    if new_recipients.is_empty() {
        return Err(FormatError::MissingRecipients);
    }

    let mut decrypt_reader = DecryptReader::new(reader, data_key.as_slice(), nonce, &header_bytes)?;

    let table_len = (header.chunk_count as usize)
        .checked_mul(CHUNK_LEN)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let mut table_bytes = vec![0u8; table_len];
    read_exact_plaintext(&mut decrypt_reader, &mut table_bytes)?;

    let mut chunks = Vec::with_capacity(header.chunk_count as usize);
    for entry in table_bytes.chunks_exact(CHUNK_LEN) {
        let chunk_id = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let chunk_type_raw = u16::from_le_bytes([entry[4], entry[5]]);
        let flags = u16::from_le_bytes([entry[6], entry[7]]);
        let offset = u64::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14], entry[15],
        ]);
        let length = u64::from_le_bytes([
            entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22], entry[23],
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

    validate_chunks(&header, &chunks)?;

    let mut new_entries = Vec::with_capacity(chunks.len());
    let new_header_len = crate::acf::header_len_v4(salt, nonce, &new_recipients)? as u64;
    let new_data_start = new_header_len
        .checked_add(table_len as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let mut offset = new_data_start;
    for (index, chunk) in chunks.iter().enumerate() {
        let next_offset =
            offset
                .checked_add(chunk.length)
                .ok_or(FormatError::ChunkLengthOverflow {
                    index: index as u32,
                })?;
        new_entries.push(ChunkEntry {
            chunk_id: chunk.chunk_id,
            chunk_type: chunk.chunk_type,
            flags: chunk.flags,
            offset,
            length: chunk.length,
        });
        offset = next_offset;
    }

    let footer_offset = offset;
    let new_header = FileHeader::new_v4(
        header.chunk_count,
        footer_offset,
        V4HeaderParams {
            cipher_id: header
                .crypto
                .as_ref()
                .and_then(|crypto| match crypto {
                    CryptoHeader::V4 { cipher_id, .. } => Some(*cipher_id),
                    _ => None,
                })
                .ok_or(FormatError::MissingCryptoHeader)?,
            kdf_id: header
                .crypto
                .as_ref()
                .and_then(|crypto| match crypto {
                    CryptoHeader::V4 { kdf_id, .. } => Some(*kdf_id),
                    _ => None,
                })
                .ok_or(FormatError::MissingCryptoHeader)?,
            kdf_params: crate::acf::KdfParamsHeader {
                memory_kib: kdf_params.memory_kib,
                iterations: kdf_params.iterations,
                parallelism: kdf_params.parallelism,
            },
            salt: salt.clone(),
            nonce: nonce.clone(),
            recipients: new_recipients,
        },
    )?;

    validate_header(&new_header)?;
    validate_chunks(&new_header, &new_entries)?;

    let header_bytes = encode_header(&new_header)?;
    writer.write_all(&header_bytes)?;

    let mut new_table_bytes = Vec::with_capacity(new_entries.len() * CHUNK_LEN);
    for entry in &new_entries {
        new_table_bytes.extend_from_slice(&encode_chunk_entry(entry));
    }

    let total_data_len: u64 = chunks.iter().map(|chunk| chunk.length).sum();
    let mut payload = RotatePayloadReader::new(
        &new_table_bytes,
        &mut decrypt_reader,
        total_data_len,
        FOOTER_V1_LEN as usize,
    );

    encrypt_stream(
        &mut payload,
        writer,
        data_key.as_slice(),
        nonce,
        &header_bytes,
    )?;

    ensure_plaintext_eof(&mut decrypt_reader)?;

    Ok(WrittenEncryptedContainer {
        header: new_header,
        chunks: new_entries,
        footer: FooterV1::new(),
    })
}

struct RotatePayloadReader<'a, R: Read> {
    table: &'a [u8],
    table_pos: usize,
    reader: &'a mut DecryptReader<R>,
    data_remaining: u64,
    footer_len: usize,
    footer_buf: Vec<u8>,
    footer_pos: usize,
    footer_loaded: bool,
    done: bool,
}

impl<'a, R: Read> RotatePayloadReader<'a, R> {
    fn new(
        table: &'a [u8],
        reader: &'a mut DecryptReader<R>,
        data_remaining: u64,
        footer_len: usize,
    ) -> Self {
        Self {
            table,
            table_pos: 0,
            reader,
            data_remaining,
            footer_len,
            footer_buf: Vec::new(),
            footer_pos: 0,
            footer_loaded: false,
            done: false,
        }
    }
}

impl<'a, R: Read> Read for RotatePayloadReader<'a, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.done {
            return Ok(0);
        }

        if self.table_pos < self.table.len() {
            let remaining = self.table.len() - self.table_pos;
            let to_copy = std::cmp::min(remaining, out.len());
            out[..to_copy].copy_from_slice(&self.table[self.table_pos..self.table_pos + to_copy]);
            self.table_pos += to_copy;
            return Ok(to_copy);
        }

        if self.data_remaining > 0 {
            let to_read = std::cmp::min(self.data_remaining, out.len() as u64) as usize;
            let read = self.reader.read(&mut out[..to_read])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated encrypted payload",
                ));
            }
            self.data_remaining = self
                .data_remaining
                .checked_sub(read as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "payload underflow"))?;
            return Ok(read);
        }

        if !self.footer_loaded {
            self.footer_buf.resize(self.footer_len, 0);
            read_exact_plaintext(self.reader, &mut self.footer_buf)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.footer_loaded = true;
        }

        if self.footer_pos < self.footer_buf.len() {
            let remaining = self.footer_buf.len() - self.footer_pos;
            let to_copy = std::cmp::min(remaining, out.len());
            out[..to_copy]
                .copy_from_slice(&self.footer_buf[self.footer_pos..self.footer_pos + to_copy]);
            self.footer_pos += to_copy;
            return Ok(to_copy);
        }

        self.done = true;
        Ok(0)
    }
}

fn select_data_key_v3(
    recipients: &[RecipientEntry],
    key_material: &[u8],
    recipient_type: WrapType,
    kdf_params: KdfParams,
    salt: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let mut has_candidate = false;
    let mut derived: Option<Zeroizing<Vec<u8>>> = None;

    for recipient in recipients {
        if recipient.recipient_type != recipient_type {
            continue;
        }
        has_candidate = true;
        if derived.is_none() {
            derived = Some(aegis_core::crypto::kdf::derive_key(
                key_material,
                salt,
                kdf_params,
            )?);
        }
        let derived = derived.as_ref().ok_or(FormatError::MissingCryptoHeader)?;
        let aad = recipient_aad(
            recipient.recipient_id,
            recipient.recipient_type,
            recipient.wrap_alg,
        );
        match unwrap_key_with_aad(derived.as_slice(), &recipient.wrapped_key, &aad) {
            Ok(key) => return Ok(key),
            Err(err) => {
                if !matches!(err, aegis_core::crypto::CryptoError::AuthFailed) {
                    return Err(FormatError::Crypto(err));
                }
            }
        }
    }

    if !has_candidate {
        return Err(FormatError::RecipientTypeNotFound);
    }

    Err(FormatError::Crypto(
        aegis_core::crypto::CryptoError::AuthFailed,
    ))
}

fn select_data_key_v4(
    recipients: &[RecipientEntry],
    key_material: &[u8],
    recipient_type: WrapType,
    kdf_params: KdfParams,
    salt: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let mut has_candidate = false;
    let mut derived: Option<Zeroizing<Vec<u8>>> = None;
    let mut private_key = None;
    let mut computed_pubkey = None;

    if recipient_type == WrapType::PublicKey {
        if key_material.len() != X25519_KEY_LEN {
            return Err(FormatError::Crypto(
                aegis_core::crypto::CryptoError::InvalidKeyLength {
                    expected: X25519_KEY_LEN,
                    found: key_material.len(),
                },
            ));
        }
        let mut key_bytes = [0u8; X25519_KEY_LEN];
        key_bytes.copy_from_slice(key_material);
        computed_pubkey = Some(public_key_from_private(&key_bytes));
        private_key = Some(key_bytes);
    }

    for recipient in recipients {
        if recipient.recipient_type != recipient_type {
            continue;
        }
        has_candidate = true;

        match recipient_type {
            WrapType::Keyfile | WrapType::Password => {
                if derived.is_none() {
                    derived = Some(aegis_core::crypto::kdf::derive_key(
                        key_material,
                        salt,
                        kdf_params,
                    )?);
                }
                let derived = derived.as_ref().ok_or(FormatError::MissingCryptoHeader)?;
                let aad = recipient_aad_v4(
                    recipient.recipient_id,
                    recipient.recipient_type,
                    recipient.wrap_alg,
                    None,
                    None,
                );
                match unwrap_key_with_aad(derived.as_slice(), &recipient.wrapped_key, &aad) {
                    Ok(key) => return Ok(key),
                    Err(err) => {
                        if !matches!(err, aegis_core::crypto::CryptoError::AuthFailed) {
                            return Err(FormatError::Crypto(err));
                        }
                    }
                }
            }
            WrapType::PublicKey => {
                let private_key = private_key
                    .as_ref()
                    .ok_or(FormatError::MissingRecipientKeyMaterial)?;
                let recipient_pubkey = recipient
                    .recipient_pubkey
                    .as_ref()
                    .ok_or(FormatError::MissingRecipientPublicKey)?;
                let ephemeral_pubkey = recipient
                    .ephemeral_pubkey
                    .as_ref()
                    .ok_or(FormatError::MissingRecipientEphemeralKey)?;
                let computed_pubkey = computed_pubkey
                    .as_ref()
                    .ok_or(FormatError::MissingRecipientKeyMaterial)?;
                if computed_pubkey != recipient_pubkey {
                    continue;
                }
                let derived = derive_wrapping_key(private_key, ephemeral_pubkey)?;
                let aad = recipient_aad_v4(
                    recipient.recipient_id,
                    recipient.recipient_type,
                    recipient.wrap_alg,
                    Some(recipient_pubkey),
                    Some(ephemeral_pubkey),
                );
                match unwrap_key_with_aad(derived.as_slice(), &recipient.wrapped_key, &aad) {
                    Ok(key) => return Ok(key),
                    Err(err) => {
                        if !matches!(err, aegis_core::crypto::CryptoError::AuthFailed) {
                            return Err(FormatError::Crypto(err));
                        }
                    }
                }
            }
        }
    }

    if !has_candidate {
        return Err(FormatError::RecipientTypeNotFound);
    }

    Err(FormatError::Crypto(
        aegis_core::crypto::CryptoError::AuthFailed,
    ))
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
    let mut buffer = [0u8; IO_BUFFER_SIZE];

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
    let mut buffer = [0u8; IO_BUFFER_SIZE];

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

fn copy_exact_plaintext<R: Read, W: Write + ?Sized>(
    reader: &mut DecryptReader<R>,
    writer: &mut W,
    mut len: u64,
) -> Result<(), FormatError> {
    let mut buffer = [0u8; IO_BUFFER_SIZE];

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
    let mut buffer = [0u8; IO_BUFFER_SIZE];

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
