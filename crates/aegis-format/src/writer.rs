use std::io::{self, Read, Write};

use aegis_core::Crc32;

use crate::acf::{
    encode_chunk_entry, encode_footer, encode_header, ChecksumType, ChunkEntry, ChunkType,
    FileHeader, Footer, FormatError, CHUNK_LEN, HEADER_LEN,
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
    pub footer: Footer,
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
    let data_start = (HEADER_LEN as u64)
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

    let header = FileHeader::new(chunk_count, offset);
    validate_header(&header)?;
    validate_chunks(&header, &entries)?;

    let mut crc = Crc32::new();
    {
        let mut checksum_writer = ChecksumWriter::new(writer, &mut crc);

        let header_bytes = encode_header(&header);
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
    let footer = Footer::new(ChecksumType::Crc32, checksum);
    let footer_bytes = encode_footer(&footer);
    writer.write_all(&footer_bytes).map_err(map_io)?;

    Ok(WrittenContainer {
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

fn map_io(err: io::Error) -> FormatError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        FormatError::Truncated
    } else {
        FormatError::Io(err)
    }
}
