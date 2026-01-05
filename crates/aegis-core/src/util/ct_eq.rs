/// Constant-time-ish equality for byte slices.
///
/// Limitations:
/// - Length differences still influence timing due to iteration count.
/// - This is a best-effort helper for non-secret comparisons today.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = core::cmp::max(a.len(), b.len());
    let mut diff = (a.len() ^ b.len()) as u64;

    for i in 0..max_len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as u64;
    }

    diff == 0
}
