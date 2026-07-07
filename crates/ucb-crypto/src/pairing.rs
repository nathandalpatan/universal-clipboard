//! Pairing verification short-authentication-string (PAIR-2).

/// Derive the 6-digit pairing code for two device public keys.
///
/// The two keys are sorted bytewise so both peers compute the same value,
/// hashed with BLAKE3, and the first 4 bytes are taken as a big-endian `u32`,
/// reduced mod 1_000_000 and zero-padded to six digits.
pub fn pairing_code(pk_a: &[u8; 32], pk_b: &[u8; 32]) -> String {
    let (lo, hi) = if pk_a <= pk_b { (pk_a, pk_b) } else { (pk_b, pk_a) };

    let mut hasher = blake3::Hasher::new();
    hasher.update(lo);
    hasher.update(hi);
    let digest = hasher.finalize();
    let b = digest.as_bytes();

    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    format!("{:06}", n % 1_000_000)
}
