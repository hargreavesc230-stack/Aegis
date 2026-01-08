#![deny(warnings)]
#![deny(clippy::all)]

pub mod acf;
pub mod reader;
pub mod validate;
pub mod writer;

pub use acf::{
    ChecksumType, ChunkEntry, ChunkType, CryptoHeader, FileHeader, FooterV0, FooterV1, FormatError,
    KdfParamsHeader, RecipientEntry, V2HeaderParams, V3HeaderParams, V4HeaderParams, WrapAlg,
    WrapType, ACF_VERSION_V0, ACF_VERSION_V1, ACF_VERSION_V2, ACF_VERSION_V3, ACF_VERSION_V4,
    CHUNK_LEN, FILE_MAGIC, FOOTER_MAGIC, HEADER_BASE_LEN, MAX_CHUNK_COUNT, MAX_WRAPPED_KEY_LEN,
    RECIPIENT_AAD_LEN, RECIPIENT_ENTRY_BASE_LEN, RECIPIENT_EPHEMERAL_KEY_LEN,
    RECIPIENT_PUBLIC_EXTRA_LEN, RECIPIENT_PUBLIC_KEY_LEN,
};
pub use reader::{
    decrypt_container, decrypt_container_v1_with_outputs, decrypt_container_v2,
    decrypt_container_v2_with_outputs, decrypt_container_v3, decrypt_container_v3_with_outputs,
    decrypt_container_v4, decrypt_container_v4_with_outputs, extract_data_chunk, read_container,
    read_container_with_status, read_header, rotate_container_v3, rotate_container_v4,
    DecryptedContainer, ParsedContainer,
};
pub use writer::{
    write_container, write_encrypted_container, write_encrypted_container_password,
    write_encrypted_container_v2, write_encrypted_container_v3,
    write_encrypted_container_v3_with_kdf, write_encrypted_container_v4,
    write_encrypted_container_v4_with_kdf, RecipientSpec, WriteChunkSource, WrittenContainer,
    WrittenEncryptedContainer,
};
