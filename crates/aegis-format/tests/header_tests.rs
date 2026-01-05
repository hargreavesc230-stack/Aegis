use aegis_format::{
    read_header, write_header, ContainerHeader, FormatError, Version, HEADER_LEN, MAGIC,
};
use aegis_testkit::{
    invalid_magic_bytes, invalid_version_bytes, sample_header_bytes, truncated_header_bytes,
};

#[test]
fn header_roundtrip() {
    let header = ContainerHeader {
        version: Version::V1,
        flags: 0xA5A5_5A5A,
    };

    let mut buf = Vec::new();
    write_header(&mut buf, &header).expect("write header");

    let parsed = read_header(&mut buf.as_slice()).expect("read header");
    assert_eq!(parsed, header);
}

#[test]
fn invalid_magic() {
    let bytes = invalid_magic_bytes();
    let err = read_header(&mut bytes.as_slice()).unwrap_err();
    assert!(matches!(err, FormatError::InvalidMagic { .. }));
}

#[test]
fn invalid_version() {
    let bytes = invalid_version_bytes();
    let err = read_header(&mut bytes.as_slice()).unwrap_err();
    assert!(matches!(err, FormatError::UnsupportedVersion(_)));
}

#[test]
fn truncated_input() {
    let bytes = truncated_header_bytes();
    let err = read_header(&mut bytes.as_slice()).unwrap_err();
    assert!(matches!(err, FormatError::Truncated));
}

#[test]
fn testkit_matches_format_constants() {
    let bytes = sample_header_bytes();
    assert!(bytes.len() >= HEADER_LEN);
    assert_eq!(&bytes[0..4], &MAGIC);
}
