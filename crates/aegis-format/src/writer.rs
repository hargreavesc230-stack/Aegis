use std::io::{self, Read, Write};

use aegis_core::crypto::aead::{encrypt_stream, generate_nonce};
use aegis_core::crypto::ids::{CipherId, KdfId};
use aegis_core::crypto::kdf::{derive_key, generate_salt, KdfParams, DEFAULT_SALT_LEN};
use aegis_core::Crc32;

use crate::acf::{
    encode_chunk_entry, encode_footer_v0, encode_footer_v1, encode_header, ChunkEntry, ChunkType,
    FileHeader, FooterV0, FooterV1, FormatError, CHUNK_LEN, HEADER_BASE_LEN,
};
use crate::validate::{validate_chunks, validate_header};

pub struct WriteChunkSource {
    pub chunk_id: u32,
    pub chunk_type: ChunkType,
    pub flags: u16,
    pub length: u64,
    pub reader: Box<dyn Read>,
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
    if chunks.len() > u32::MAX as usize {
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
    if chunks.len() > u32::MAX as usize {
        return Err(FormatError::ChunkCountTooLarge);
    }

    let chunk_count = chunks.len() as u32;
    let salt = generate_salt(DEFAULT_SALT_LEN)?;
    let nonce = generate_nonce()?;

    let header_len = crate::acf::header_len_v1(&salt, &nonce)? as u64;
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

    let header = FileHeader::new_v1(
        chunk_count,
        footer_offset,
        CipherId::XChaCha20Poly1305,
        KdfId::Argon2id,
        salt.to_vec(),
        nonce.to_vec(),
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

    let derived = derive_key(key_material, &salt, KdfParams::default())?;
    let mut payload = PayloadReader::new(&table_bytes, chunks, &footer_bytes);
    encrypt_stream(
        &mut payload,
        writer,
        derived.as_slice(),
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
    let mut buffer = [0u8; 8192];

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
