use std::io::{self, Cursor, Read, Write};

use aegis_format::{
    read_container, read_container_with_status, write_container, ChunkType, FormatError,
    WriteChunkSource, CHUNK_LEN, HEADER_BASE_LEN,
};
use aegis_testkit::{flip_byte, sample_bytes};

fn make_chunk(chunk_id: u32, chunk_type: ChunkType, data: Vec<u8>) -> WriteChunkSource {
    WriteChunkSource {
        chunk_id,
        chunk_type,
        flags: 0,
        length: data.len() as u64,
        reader: Box::new(Cursor::new(data)),
    }
}

fn build_container_bytes(chunks: &mut [WriteChunkSource]) -> Vec<u8> {
    let mut out = Vec::new();
    let _written = write_container(&mut out, chunks).expect("write container");
    out
}

#[test]
fn header_roundtrip() {
    let data = sample_bytes(4);
    let mut chunks = vec![make_chunk(1, ChunkType::Data, data)];
    let bytes = build_container_bytes(&mut chunks);

    let parsed = read_container(&mut Cursor::new(bytes)).expect("read container");
    assert_eq!(parsed.header.chunk_count, 1);
    assert!(parsed.checksum_valid);
}

#[test]
fn chunk_table_roundtrip_multiple_chunks() {
    let mut chunks = vec![
        make_chunk(1, ChunkType::Data, sample_bytes(10)),
        make_chunk(2, ChunkType::Metadata, sample_bytes(5)),
    ];

    let bytes = build_container_bytes(&mut chunks);
    let parsed = read_container(&mut Cursor::new(bytes)).expect("read container");

    assert_eq!(parsed.chunks.len(), 2);
    assert_eq!(parsed.chunks[0].chunk_type, ChunkType::Data);
    assert_eq!(parsed.chunks[1].chunk_type, ChunkType::Metadata);

    let expected_first_offset = HEADER_BASE_LEN as u64 + (2 * CHUNK_LEN) as u64;
    let expected_second_offset = expected_first_offset + parsed.chunks[0].length;
    assert_eq!(parsed.chunks[0].offset, expected_first_offset);
    assert_eq!(parsed.chunks[1].offset, expected_second_offset);
}

#[test]
fn overlapping_chunk_detection() {
    let mut chunks = vec![
        make_chunk(1, ChunkType::Data, sample_bytes(10)),
        make_chunk(2, ChunkType::Metadata, sample_bytes(5)),
    ];

    let mut bytes = build_container_bytes(&mut chunks);

    let second_offset_pos = HEADER_BASE_LEN + CHUNK_LEN + 8;
    let overlapping_offset = (HEADER_BASE_LEN as u64 + (2 * CHUNK_LEN) as u64).to_le_bytes();
    bytes[second_offset_pos..second_offset_pos + 8].copy_from_slice(&overlapping_offset);

    let err = read_container(&mut Cursor::new(bytes)).unwrap_err();
    assert!(matches!(err, FormatError::OverlappingChunk { .. }));
}

#[test]
fn truncated_file_detection() {
    let mut chunks = vec![make_chunk(1, ChunkType::Data, sample_bytes(10))];
    let mut bytes = build_container_bytes(&mut chunks);
    bytes.truncate(bytes.len() - 3);

    let err = read_container(&mut Cursor::new(bytes)).unwrap_err();
    assert!(matches!(err, FormatError::Truncated));
}

#[test]
fn corrupted_checksum_detection() {
    let mut chunks = vec![make_chunk(1, ChunkType::Data, sample_bytes(10))];
    let mut bytes = build_container_bytes(&mut chunks);

    let data_offset = HEADER_BASE_LEN + CHUNK_LEN;
    flip_byte(&mut bytes, data_offset);

    let err = read_container(&mut Cursor::new(bytes)).unwrap_err();
    assert!(matches!(err, FormatError::ChecksumMismatch { .. }));
}

#[test]
fn large_stream_write_does_not_allocate() {
    let chunk_len = 5 * 1024 * 1024u64;
    let mut chunks = vec![WriteChunkSource {
        chunk_id: 1,
        chunk_type: ChunkType::Data,
        flags: 0,
        length: chunk_len,
        reader: Box::new(ZeroReader {
            remaining: chunk_len,
        }),
    }];

    let mut sink = CountingWriter::new();
    let written = write_container(&mut sink, &mut chunks).expect("write container");

    assert_eq!(written.chunks.len(), 1);
    let expected_len =
        HEADER_BASE_LEN as u64 + CHUNK_LEN as u64 + chunk_len + written.footer.footer_len as u64;
    assert_eq!(sink.bytes_written(), expected_len);
}

#[test]
fn checksum_status_for_inspect() {
    let mut chunks = vec![make_chunk(1, ChunkType::Data, sample_bytes(4))];
    let mut bytes = build_container_bytes(&mut chunks);
    flip_byte(&mut bytes, HEADER_BASE_LEN + CHUNK_LEN);

    let parsed = read_container_with_status(&mut Cursor::new(bytes)).expect("inspect read");
    assert!(!parsed.checksum_valid);
}

struct ZeroReader {
    remaining: u64,
}

impl Read for ZeroReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }

        let to_write = std::cmp::min(self.remaining, buf.len() as u64) as usize;
        buf[..to_write].fill(0);
        self.remaining -= to_write as u64;
        Ok(to_write)
    }
}

struct CountingWriter {
    bytes: u64,
}

impl CountingWriter {
    fn new() -> Self {
        Self { bytes: 0 }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
