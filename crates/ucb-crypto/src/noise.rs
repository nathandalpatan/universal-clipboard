//! Shared Noise parameters and framing constants.

use snow::params::NoiseParams;

/// The fixed Noise pattern for all sessions (PAIR-3).
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum length-prefixed frame size on the wire: 16 MiB (ARCHITECTURE.md).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// snow's hard per-message ciphertext limit.
pub const MAX_NOISE_MESSAGE: usize = 65535;

/// AEAD tag length added to each Noise message.
pub const TAG_LEN: usize = 16;

/// Largest plaintext we hand to a single `write_message` call so the
/// resulting ciphertext stays within [`MAX_NOISE_MESSAGE`].
pub const MAX_PLAINTEXT_CHUNK: usize = MAX_NOISE_MESSAGE - TAG_LEN; // 65519

/// Parse the fixed pattern into `NoiseParams`.
///
/// The pattern is a compile-time constant known to be valid, so a parse
/// failure is a programmer error rather than a runtime condition.
pub fn noise_params() -> NoiseParams {
    NOISE_PATTERN
        .parse()
        .expect("static Noise pattern must parse")
}
