use ark_ar1cs_format::ArcsError;

/// Structured errors returned by `.arwtns` parsing, validation, and binding.
///
/// Marked `#[non_exhaustive]` (CQ-2) so future variants can be added without a
/// breaking change. Variants are structured (CQ-4) — never `String` payloads —
/// so callers can match exactly on the failure mode.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ArwtnsError {
    #[error("invalid magic bytes")]
    BadMagic,

    #[error("unsupported version: {0:#x}")]
    UnsupportedVersion(u8),

    #[error("reserved header bytes must be zero")]
    ReservedNotZero,

    #[error("curve mismatch: header={header:#x}, embedded={embedded:#x}")]
    CurveMismatch { header: u8, embedded: u8 },

    #[error("ar1cs_blake3 mismatch")]
    Ar1csBlake3Mismatch,

    #[error("Blake3 trailer checksum mismatch")]
    ChecksumMismatch,

    #[error("file exceeds maximum allowed size")]
    FileTooLarge,

    #[error("unexpected trailing bytes: {0} byte(s) after body")]
    TrailingBytes(u64),

    #[error("count mismatch on field {field}: header={header}, actual={actual}")]
    CountMismatch {
        field: &'static str,
        header: u64,
        actual: u64,
    },

    #[error("body length mismatch: expected {expected} bytes, actual {actual}")]
    BodyLengthMismatch { expected: u64, actual: u64 },

    #[error(transparent)]
    Format(#[from] ArcsError),

    #[error(transparent)]
    Serialization(#[from] ark_serialize::SerializationError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
