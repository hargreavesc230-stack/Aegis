#![deny(warnings)]
#![deny(clippy::all)]

pub mod acf;
pub mod reader;
pub mod validate;
pub mod writer;

pub use acf::{
    ChecksumType, ChunkEntry, ChunkType, CryptoHeader, FileHeader, FooterV0, FooterV1, FormatError,
    ACF_VERSION_V0, ACF_VERSION_V1, CHUNK_LEN, FILE_MAGIC, FOOTER_MAGIC, HEADER_BASE_LEN,
};
pub use reader::{
    decrypt_container, extract_data_chunk, read_container, read_container_with_status, read_header,
    DecryptedContainer, ParsedContainer,
};
pub use writer::{
    write_container, write_encrypted_container, WriteChunkSource, WrittenContainer,
    WrittenEncryptedContainer,
};
