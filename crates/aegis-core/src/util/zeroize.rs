#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Best-effort zeroization for in-memory buffers.
///
/// Limitations:
/// - Without the `zeroize` feature, this is a simple overwrite that may be
///   optimized by the compiler.
/// - Even with `zeroize`, zeroization does not guarantee complete removal on
///   all platforms or in the presence of OS-level paging.
#[cfg(feature = "zeroize")]
pub fn zeroize_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(not(feature = "zeroize"))]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
}
