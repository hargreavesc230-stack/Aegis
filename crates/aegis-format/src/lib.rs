#![deny(warnings)]
#![deny(clippy::all)]

pub mod acf;
pub mod reader;
pub mod validate;
pub mod writer;

pub use acf::{
    ChecksumType, ChunkEntry, ChunkType, CryptoHeader, FileHeader, FooterV0, FooterV1, FormatError,
    KdfParamsHeader, V2HeaderParams, WrapType, ACF_VERSION_V0, ACF_VERSION_V1, ACF_VERSION_V2,
    CHUNK_LEN, FILE_MAGIC, FOOTER_MAGIC, HEADER_BASE_LEN, MAX_CHUNK_COUNT, MAX_WRAPPED_KEY_LEN,
};
pub use reader::{
    decrypt_container, decrypt_container_v2, extract_data_chunk, read_container,
    read_container_with_status, read_header, DecryptedContainer, ParsedContainer,
};
pub use writer::{
    write_container, write_encrypted_container, write_encrypted_container_password,
    write_encrypted_container_v2, WriteChunkSource, WrittenContainer, WrittenEncryptedContainer,
};
