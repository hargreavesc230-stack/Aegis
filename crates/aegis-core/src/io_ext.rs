use std::io::{self, Read, Write};

pub fn read_exact_or_err<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<()> {
    reader.read_exact(buf)
}

pub fn skip_exact<R: Read>(reader: &mut R, mut len: u64) -> io::Result<()> {
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
        len -= read as u64;
    }

    Ok(())
}

pub fn copy_exact<R: Read, W: Write>(
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
