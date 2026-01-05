use std::io::{self, Read, Write};

use aegis_core::io_ext::read_exact_or_err;
use aegis_core::Crc32;

use crate::acf::{
    ChecksumType, ChunkEntry, ChunkType, FileHeader, Footer, FormatError, CHUNK_LEN, FILE_MAGIC,
    FOOTER_MAGIC, HEADER_LEN,
};
use crate::validate::{validate_chunks, validate_header};

#[derive(Debug, Clone)]
pub struct ParsedContainer {
    pub header: FileHeader,
    pub chunks: Vec<ChunkEntry>,
    pub footer: Footer,
    pub checksum_valid: bool,
    pub computed_checksum: u32,
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

fn read_container_internal<R: Read>(
    reader: &mut R,
    mut data_out: Option<&mut dyn Write>,
    strict_checksum: bool,
) -> Result<ParsedContainer, FormatError> {
    let mut crc = Crc32::new();

    let mut header_buf = [0u8; HEADER_LEN];
    read_exact_update(reader, &mut header_buf, &mut crc)?;

    let magic = [
        header_buf[0],
        header_buf[1],
        header_buf[2],
        header_buf[3],
        header_buf[4],
        header_buf[5],
        header_buf[6],
        header_buf[7],
    ];

    if magic != FILE_MAGIC {
        return Err(FormatError::InvalidMagic { found: magic });
    }

    let header = FileHeader {
        version: u16::from_le_bytes([header_buf[8], header_buf[9]]),
        header_len: u16::from_le_bytes([header_buf[10], header_buf[11]]),
        flags: u32::from_le_bytes([
            header_buf[12],
            header_buf[13],
            header_buf[14],
            header_buf[15],
        ]),
        chunk_count: u32::from_le_bytes([
            header_buf[16],
            header_buf[17],
            header_buf[18],
            header_buf[19],
        ]),
        chunk_table_offset: u64::from_le_bytes([
            header_buf[20],
            header_buf[21],
            header_buf[22],
            header_buf[23],
            header_buf[24],
            header_buf[25],
            header_buf[26],
            header_buf[27],
        ]),
        footer_offset: u64::from_le_bytes([
            header_buf[28],
            header_buf[29],
            header_buf[30],
            header_buf[31],
            header_buf[32],
            header_buf[33],
            header_buf[34],
            header_buf[35],
        ]),
    };

    validate_header(&header)?;

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

    let footer = read_footer(reader)?;

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

fn read_footer<R: Read>(reader: &mut R) -> Result<Footer, FormatError> {
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

    Ok(Footer {
        footer_len,
        checksum_type,
        checksum,
    })
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

fn read_exact_truncated<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), FormatError> {
    match read_exact_or_err(reader, buf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(FormatError::Truncated),
        Err(err) => Err(FormatError::Io(err)),
    }
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

fn ensure_eof<R: Read>(reader: &mut R) -> Result<(), FormatError> {
    let mut buf = [0u8; 1];
    match reader.read(&mut buf) {
        Ok(0) => Ok(()),
        Ok(_) => Err(FormatError::TrailingData),
        Err(err) => Err(FormatError::Io(err)),
    }
}
