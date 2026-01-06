#![deny(warnings)]
#![deny(clippy::all)]

pub mod acf;
pub mod reader;
pub mod validate;
pub mod writer;

pub use acf::{
    ChecksumType, ChunkEntry, ChunkType, CryptoHeader, FileHeader, FooterV0, FooterV1, FormatError,
    KdfParamsHeader, RecipientEntry, V2HeaderParams, V3HeaderParams, WrapAlg, WrapType,
    ACF_VERSION_V0, ACF_VERSION_V1, ACF_VERSION_V2, ACF_VERSION_V3, CHUNK_LEN, FILE_MAGIC,
    FOOTER_MAGIC, HEADER_BASE_LEN, MAX_CHUNK_COUNT, MAX_WRAPPED_KEY_LEN, RECIPIENT_AAD_LEN,
    RECIPIENT_ENTRY_BASE_LEN,
};
pub use reader::{
    decrypt_container, decrypt_container_v2, decrypt_container_v3, extract_data_chunk,
    read_container, read_container_with_status, read_header, rotate_container_v3,
    DecryptedContainer, ParsedContainer,
};
pub use writer::{
    write_container, write_encrypted_container, write_encrypted_container_password,
    write_encrypted_container_v2, write_encrypted_container_v3, RecipientSpec, WriteChunkSource,
    WrittenContainer, WrittenEncryptedContainer,
};
