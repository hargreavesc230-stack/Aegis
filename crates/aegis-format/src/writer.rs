use std::io::{self, Read, Write};

use aegis_core::crypto::aead::{encrypt_stream, generate_nonce, AEAD_KEY_LEN};
use aegis_core::crypto::ids::{CipherId, KdfId};
use aegis_core::crypto::kdf::{
    derive_key, generate_salt, KdfParams, DEFAULT_KEYFILE_PARAMS, DEFAULT_PASSWORD_PARAMS,
    DEFAULT_SALT_LEN,
};
use aegis_core::crypto::keyfile::generate_key;
use aegis_core::crypto::public_key::{derive_wrapping_key, generate_keypair};
use aegis_core::crypto::wrap::{wrap_key, wrap_key_with_aad};
use aegis_core::Crc32;

use crate::acf::{
    encode_chunk_entry, encode_footer_v0, encode_footer_v1, encode_header, recipient_aad,
    recipient_aad_v4, ChunkEntry, ChunkType, FileHeader, FooterV0, FooterV1, FormatError,
    RecipientEntry, V3HeaderParams, V4HeaderParams, WrapAlg, WrapType, CHUNK_LEN, HEADER_BASE_LEN,
    MAX_CHUNK_COUNT,
};
use crate::validate::{validate_chunks, validate_header};

// 64 KiB buffers align with AEAD chunking for better throughput.
const IO_BUFFER_SIZE: usize = 64 * 1024;

pub struct WriteChunkSource {
    pub chunk_id: u32,
    pub chunk_type: ChunkType,
    pub flags: u16,
    pub length: u64,
    pub reader: Box<dyn Read>,
}

pub struct RecipientSpec<'a> {
    pub recipient_id: u32,
    pub recipient_type: WrapType,
    pub key_material: Option<&'a [u8]>,
    pub public_key: Option<[u8; crate::acf::RECIPIENT_PUBLIC_KEY_LEN]>,
}

#[derive(Debug, Clone)]
pub struct WrittenContainer {
    pub header: FileHeader,
    pub chunks: Vec<ChunkEntry>,
    pub footer: FooterV0,
}

#[derive(Debug, Clone)]
pub struct WrittenEncryptedContainer {
    pub header: FileHeader,
    pub chunks: Vec<ChunkEntry>,
    pub footer: FooterV1,
}

pub fn write_container<W: Write>(
    writer: &mut W,
    chunks: &mut [WriteChunkSource],
) -> Result<WrittenContainer, FormatError> {
    if chunks.len() > MAX_CHUNK_COUNT as usize {
        return Err(FormatError::ChunkCountTooLarge);
    }

    let chunk_count = chunks.len() as u32;
    let table_len = (chunk_count as u64)
        .checked_mul(CHUNK_LEN as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let data_start = (HEADER_BASE_LEN as u64)
        .checked_add(table_len)
        .ok_or(FormatError::ChunkCountTooLarge)?;

    let mut entries = Vec::with_capacity(chunks.len());
    let mut offset = data_start;

    for (index, chunk) in chunks.iter().enumerate() {
        let next_offset =
            offset
                .checked_add(chunk.length)
                .ok_or(FormatError::ChunkLengthOverflow {
                    index: index as u32,
                })?;

        entries.push(ChunkEntry {
            chunk_id: chunk.chunk_id,
            chunk_type: chunk.chunk_type,
            flags: chunk.flags,
            offset,
            length: chunk.length,
        });

        offset = next_offset;
    }

    let header = FileHeader::new_v0(chunk_count, offset);
    validate_header(&header)?;
    validate_chunks(&header, &entries)?;

    let header_bytes = encode_header(&header)?;

    let mut crc = Crc32::new();
    {
        let mut checksum_writer = ChecksumWriter::new(writer, &mut crc);

        checksum_writer.write_all(&header_bytes).map_err(map_io)?;

        for entry in &entries {
            let entry_bytes = encode_chunk_entry(entry);
            checksum_writer.write_all(&entry_bytes).map_err(map_io)?;
        }

        for chunk in chunks.iter_mut() {
            copy_exact_with_checksum(&mut chunk.reader, &mut checksum_writer, chunk.length)
                .map_err(map_io)?;
        }
    }

    let checksum = crc.finalize();
    let footer = FooterV0::new(crate::acf::ChecksumType::Crc32, checksum);
    let footer_bytes = encode_footer_v0(&footer);
    writer.write_all(&footer_bytes).map_err(map_io)?;

    Ok(WrittenContainer {
        header,
        chunks: entries,
        footer,
    })
}

pub fn write_encrypted_container<W: Write>(
    writer: &mut W,
    chunks: &mut [WriteChunkSource],
    key_material: &[u8],
) -> Result<WrittenEncryptedContainer, FormatError> {
    write_encrypted_container_v2(
        writer,
        chunks,
        key_material,
        WrapType::Keyfile,
        DEFAULT_KEYFILE_PARAMS,
    )
}

pub fn write_encrypted_container_password<W: Write>(
    writer: &mut W,
    chunks: &mut [WriteChunkSource],
    password: &[u8],
) -> Result<WrittenEncryptedContainer, FormatError> {
    write_encrypted_container_v2(
        writer,
        chunks,
        password,
        WrapType::Password,
        DEFAULT_PASSWORD_PARAMS,
    )
}

pub fn write_encrypted_container_v2<W: Write>(
    writer: &mut W,
    chunks: &mut [WriteChunkSource],
    key_material: &[u8],
    wrap_type: WrapType,
    kdf_params: KdfParams,
) -> Result<WrittenEncryptedContainer, FormatError> {
    if chunks.len() > MAX_CHUNK_COUNT as usize {
        return Err(FormatError::ChunkCountTooLarge);
    }

    let chunk_count = chunks.len() as u32;
    let salt = generate_salt(DEFAULT_SALT_LEN)?;
    let nonce = generate_nonce()?;
    let data_key = generate_key(AEAD_KEY_LEN)?;

    let wrapped_key = {
        let derived = derive_key(key_material, &salt, kdf_params)?;
        wrap_key(derived.as_slice(), data_key.as_slice())?
    };

    let header_len = crate::acf::header_len_v2(&salt, &nonce, &wrapped_key)? as u64;
    let table_len = (chunk_count as u64)
        .checked_mul(CHUNK_LEN as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let data_start = header_len
        .checked_add(table_len)
        .ok_or(FormatError::ChunkCountTooLarge)?;

    let mut entries = Vec::with_capacity(chunks.len());
    let mut offset = data_start;

    for (index, chunk) in chunks.iter().enumerate() {
        let next_offset =
            offset
                .checked_add(chunk.length)
                .ok_or(FormatError::ChunkLengthOverflow {
                    index: index as u32,
                })?;

        entries.push(ChunkEntry {
            chunk_id: chunk.chunk_id,
            chunk_type: chunk.chunk_type,
            flags: chunk.flags,
            offset,
            length: chunk.length,
        });

        offset = next_offset;
    }

    let footer = FooterV1::new();
    let footer_offset = offset;

    let header = FileHeader::new_v2(
        chunk_count,
        footer_offset,
        crate::acf::V2HeaderParams {
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            kdf_params: crate::acf::KdfParamsHeader {
                memory_kib: kdf_params.memory_kib,
                iterations: kdf_params.iterations,
                parallelism: kdf_params.parallelism,
            },
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            wrap_type,
            wrapped_key,
        },
    )?;

    validate_header(&header)?;
    validate_chunks(&header, &entries)?;

    let header_bytes = encode_header(&header)?;
    writer.write_all(&header_bytes).map_err(map_io)?;

    let mut table_bytes = Vec::with_capacity(entries.len() * CHUNK_LEN);
    for entry in &entries {
        table_bytes.extend_from_slice(&encode_chunk_entry(entry));
    }

    let footer_bytes = encode_footer_v1(&footer);

    let mut payload = PayloadReader::new(&table_bytes, chunks, &footer_bytes);
    encrypt_stream(
        &mut payload,
        writer,
        data_key.as_slice(),
        &nonce,
        &header_bytes,
    )?;

    Ok(WrittenEncryptedContainer {
        header,
        chunks: entries,
        footer,
    })
}

pub fn write_encrypted_container_v3<W: Write>(
    writer: &mut W,
    chunks: &mut [WriteChunkSource],
    recipients: &[RecipientSpec<'_>],
) -> Result<WrittenEncryptedContainer, FormatError> {
    use std::collections::HashSet;

    if chunks.len() > MAX_CHUNK_COUNT as usize {
        return Err(FormatError::ChunkCountTooLarge);
    }
    if recipients.is_empty() {
        return Err(FormatError::MissingRecipients);
    }

    let mut ids = HashSet::with_capacity(recipients.len());
    let mut requires_password_params = false;
    for recipient in recipients {
        if recipient.recipient_type == WrapType::PublicKey || recipient.public_key.is_some() {
            return Err(FormatError::UnsupportedWrapType(WrapType::PublicKey as u16));
        }
        if !ids.insert(recipient.recipient_id) {
            return Err(FormatError::DuplicateRecipientId(recipient.recipient_id));
        }
        if recipient.recipient_type == WrapType::Password {
            requires_password_params = true;
        }
    }

    let kdf_params = if requires_password_params {
        DEFAULT_PASSWORD_PARAMS
    } else {
        DEFAULT_KEYFILE_PARAMS
    };

    let chunk_count = chunks.len() as u32;
    let salt = generate_salt(DEFAULT_SALT_LEN)?;
    let nonce = generate_nonce()?;
    let data_key = generate_key(AEAD_KEY_LEN)?;

    let mut recipient_entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let key_material = recipient
            .key_material
            .ok_or(FormatError::MissingRecipientKeyMaterial)?;
        let derived = derive_key(key_material, &salt, kdf_params)?;
        let wrap_alg = WrapAlg::XChaCha20Poly1305;
        let aad = recipient_aad(recipient.recipient_id, recipient.recipient_type, wrap_alg);
        let wrapped_key = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
        recipient_entries.push(RecipientEntry {
            recipient_id: recipient.recipient_id,
            recipient_type: recipient.recipient_type,
            wrap_alg,
            wrapped_key,
            recipient_pubkey: None,
            ephemeral_pubkey: None,
        });
    }

    let header_len = crate::acf::header_len_v3(&salt, &nonce, &recipient_entries)? as u64;
    let table_len = (chunk_count as u64)
        .checked_mul(CHUNK_LEN as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let data_start = header_len
        .checked_add(table_len)
        .ok_or(FormatError::ChunkCountTooLarge)?;

    let mut entries = Vec::with_capacity(chunks.len());
    let mut offset = data_start;

    for (index, chunk) in chunks.iter().enumerate() {
        let next_offset =
            offset
                .checked_add(chunk.length)
                .ok_or(FormatError::ChunkLengthOverflow {
                    index: index as u32,
                })?;

        entries.push(ChunkEntry {
            chunk_id: chunk.chunk_id,
            chunk_type: chunk.chunk_type,
            flags: chunk.flags,
            offset,
            length: chunk.length,
        });

        offset = next_offset;
    }

    let footer = FooterV1::new();
    let footer_offset = offset;

    let header = FileHeader::new_v3(
        chunk_count,
        footer_offset,
        V3HeaderParams {
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            kdf_params: crate::acf::KdfParamsHeader {
                memory_kib: kdf_params.memory_kib,
                iterations: kdf_params.iterations,
                parallelism: kdf_params.parallelism,
            },
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            recipients: recipient_entries,
        },
    )?;

    validate_header(&header)?;
    validate_chunks(&header, &entries)?;

    let header_bytes = encode_header(&header)?;
    writer.write_all(&header_bytes).map_err(map_io)?;

    let mut table_bytes = Vec::with_capacity(entries.len() * CHUNK_LEN);
    for entry in &entries {
        table_bytes.extend_from_slice(&encode_chunk_entry(entry));
    }

    let footer_bytes = encode_footer_v1(&footer);

    let mut payload = PayloadReader::new(&table_bytes, chunks, &footer_bytes);
    encrypt_stream(
        &mut payload,
        writer,
        data_key.as_slice(),
        &nonce,
        &header_bytes,
    )?;

    Ok(WrittenEncryptedContainer {
        header,
        chunks: entries,
        footer,
    })
}

pub fn write_encrypted_container_v4<W: Write>(
    writer: &mut W,
    chunks: &mut [WriteChunkSource],
    recipients: &[RecipientSpec<'_>],
) -> Result<WrittenEncryptedContainer, FormatError> {
    use std::collections::HashSet;

    if chunks.len() > MAX_CHUNK_COUNT as usize {
        return Err(FormatError::ChunkCountTooLarge);
    }
    if recipients.is_empty() {
        return Err(FormatError::MissingRecipients);
    }

    let mut ids = HashSet::with_capacity(recipients.len());
    let mut requires_password_params = false;
    let mut has_public = false;
    for recipient in recipients {
        if !ids.insert(recipient.recipient_id) {
            return Err(FormatError::DuplicateRecipientId(recipient.recipient_id));
        }
        match recipient.recipient_type {
            WrapType::Password => requires_password_params = true,
            WrapType::PublicKey => has_public = true,
            WrapType::Keyfile => {}
        }
    }

    let kdf_params = if requires_password_params {
        DEFAULT_PASSWORD_PARAMS
    } else {
        DEFAULT_KEYFILE_PARAMS
    };

    let chunk_count = chunks.len() as u32;
    let salt = generate_salt(DEFAULT_SALT_LEN)?;
    let nonce = generate_nonce()?;
    // Keep the data key in a zeroizing buffer to reduce key lifetime in memory.
    let data_key = generate_key(AEAD_KEY_LEN)?;

    let mut ephemeral_private = None;
    let mut ephemeral_public = None;
    if has_public {
        let (private, public) = generate_keypair()?;
        // The ephemeral private key is zeroized when it goes out of scope.
        ephemeral_private = Some(private);
        ephemeral_public = Some(public);
    }

    let mut recipient_entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let wrap_alg = WrapAlg::XChaCha20Poly1305;
        let (wrapped_key, recipient_pubkey, ephemeral_pubkey) = match recipient.recipient_type {
            WrapType::Keyfile | WrapType::Password => {
                let key_material = recipient
                    .key_material
                    .ok_or(FormatError::MissingRecipientKeyMaterial)?;
                let derived = derive_key(key_material, &salt, kdf_params)?;
                let aad = recipient_aad_v4(
                    recipient.recipient_id,
                    recipient.recipient_type,
                    wrap_alg,
                    None,
                    None,
                );
                let wrapped = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
                (wrapped, None, None)
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
                let wrapped = wrap_key_with_aad(derived.as_slice(), data_key.as_slice(), &aad)?;
                (wrapped, Some(public_key), Some(ephemeral_pub))
            }
        };

        recipient_entries.push(RecipientEntry {
            recipient_id: recipient.recipient_id,
            recipient_type: recipient.recipient_type,
            wrap_alg,
            wrapped_key,
            recipient_pubkey,
            ephemeral_pubkey,
        });
    }

    let header_len = crate::acf::header_len_v4(&salt, &nonce, &recipient_entries)? as u64;
    let table_len = (chunk_count as u64)
        .checked_mul(CHUNK_LEN as u64)
        .ok_or(FormatError::ChunkCountTooLarge)?;
    let data_start = header_len
        .checked_add(table_len)
        .ok_or(FormatError::ChunkCountTooLarge)?;

    let mut entries = Vec::with_capacity(chunks.len());
    let mut offset = data_start;

    for (index, chunk) in chunks.iter().enumerate() {
        let next_offset =
            offset
                .checked_add(chunk.length)
                .ok_or(FormatError::ChunkLengthOverflow {
                    index: index as u32,
                })?;

        entries.push(ChunkEntry {
            chunk_id: chunk.chunk_id,
            chunk_type: chunk.chunk_type,
            flags: chunk.flags,
            offset,
            length: chunk.length,
        });

        offset = next_offset;
    }

    let footer = FooterV1::new();
    let footer_offset = offset;

    let header = FileHeader::new_v4(
        chunk_count,
        footer_offset,
        V4HeaderParams {
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            kdf_params: crate::acf::KdfParamsHeader {
                memory_kib: kdf_params.memory_kib,
                iterations: kdf_params.iterations,
                parallelism: kdf_params.parallelism,
            },
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            recipients: recipient_entries,
        },
    )?;

    validate_header(&header)?;
    validate_chunks(&header, &entries)?;

    let header_bytes = encode_header(&header)?;
    writer.write_all(&header_bytes).map_err(map_io)?;

    let mut table_bytes = Vec::with_capacity(entries.len() * CHUNK_LEN);
    for entry in &entries {
        table_bytes.extend_from_slice(&encode_chunk_entry(entry));
    }

    let footer_bytes = encode_footer_v1(&footer);

    let mut payload = PayloadReader::new(&table_bytes, chunks, &footer_bytes);
    encrypt_stream(
        &mut payload,
        writer,
        data_key.as_slice(),
        &nonce,
        &header_bytes,
    )?;

    Ok(WrittenEncryptedContainer {
        header,
        chunks: entries,
        footer,
    })
}

struct ChecksumWriter<'a, W: Write> {
    inner: &'a mut W,
    crc: &'a mut Crc32,
}

impl<'a, W: Write> ChecksumWriter<'a, W> {
    fn new(inner: &'a mut W, crc: &'a mut Crc32) -> Self {
        Self { inner, crc }
    }
}

impl<'a, W: Write> Write for ChecksumWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.crc.update(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn copy_exact_with_checksum<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut len: u64,
) -> io::Result<()> {
    let mut buffer = [0u8; IO_BUFFER_SIZE];

    while len > 0 {
        let to_read = std::cmp::min(len, buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..to_read])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated input",
            ));
        }
        writer.write_all(&buffer[..read])?;
        len -= read as u64;
    }

    Ok(())
}

struct PayloadReader<'a> {
    table: &'a [u8],
    table_pos: usize,
    chunks: &'a mut [WriteChunkSource],
    chunk_index: usize,
    chunk_remaining: u64,
    footer: &'a [u8],
    footer_pos: usize,
    done: bool,
}

impl<'a> PayloadReader<'a> {
    fn new(table: &'a [u8], chunks: &'a mut [WriteChunkSource], footer: &'a [u8]) -> Self {
        Self {
            table,
            table_pos: 0,
            chunks,
            chunk_index: 0,
            chunk_remaining: 0,
            footer,
            footer_pos: 0,
            done: false,
        }
    }
}

impl<'a> Read for PayloadReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }

        loop {
            if self.table_pos < self.table.len() {
                let remaining = self.table.len() - self.table_pos;
                let to_copy = std::cmp::min(remaining, buf.len());
                buf[..to_copy]
                    .copy_from_slice(&self.table[self.table_pos..self.table_pos + to_copy]);
                self.table_pos += to_copy;
                return Ok(to_copy);
            }

            if self.chunk_index < self.chunks.len() {
                if self.chunk_remaining == 0 {
                    self.chunk_remaining = self.chunks[self.chunk_index].length;
                }

                if self.chunk_remaining == 0 {
                    self.chunk_index += 1;
                    continue;
                }

                let to_read = std::cmp::min(self.chunk_remaining, buf.len() as u64) as usize;
                let read = self.chunks[self.chunk_index]
                    .reader
                    .read(&mut buf[..to_read])?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated input",
                    ));
                }
                self.chunk_remaining -= read as u64;
                if self.chunk_remaining == 0 {
                    self.chunk_index += 1;
                }
                return Ok(read);
            }

            if self.footer_pos < self.footer.len() {
                let remaining = self.footer.len() - self.footer_pos;
                let to_copy = std::cmp::min(remaining, buf.len());
                buf[..to_copy]
                    .copy_from_slice(&self.footer[self.footer_pos..self.footer_pos + to_copy]);
                self.footer_pos += to_copy;
                return Ok(to_copy);
            }

            self.done = true;
            return Ok(0);
        }
    }
}

fn map_io(err: io::Error) -> FormatError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        FormatError::Truncated
    } else {
        FormatError::Io(err)
    }
}
