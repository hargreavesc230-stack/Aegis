#![deny(warnings)]
#![deny(clippy::all)]

pub mod acf;
pub mod reader;
pub mod validate;
pub mod writer;

pub use acf::{
    ChecksumType, ChunkEntry, ChunkType, FileHeader, Footer, FormatError, ACF_VERSION, CHUNK_LEN,
    FILE_MAGIC, FOOTER_MAGIC, HEADER_LEN,
};
pub use reader::read_container_with_status;
pub use reader::{extract_data_chunk, read_container, ParsedContainer};
pub use writer::{write_container, WriteChunkSource, WrittenContainer};
