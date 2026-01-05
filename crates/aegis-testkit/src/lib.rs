#![deny(warnings)]
#![deny(clippy::all)]

pub fn sample_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

pub fn flip_byte(buf: &mut [u8], index: usize) {
    if buf.is_empty() {
        return;
    }

    let idx = index % buf.len();
    buf[idx] ^= 0xFF;
}
