use crate::format::header::CurveId;

/// Errors raised by `.ar1cs` envelope codec (read / validate).
///
/// Marked `#[non_exhaustive]` (CQ-2) so future variants are non-breaking
/// for downstream `match` sites. Variants stay structured (CQ-4) — never
/// `String` payloads except `ValidationFailed`, which mirrors arkworks's
/// free-form failure messages from `ConstraintSystem` validation.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ArcsError {
    #[error("invalid magic bytes")]
    InvalidMagic,

    #[error("unsupported version: {0:#x}")]
    UnsupportedVersion(u8),

    #[error("unsupported curve ID: {0:#x}")]
    UnsupportedCurve(u8),

    /// The file's curve ID doesn't match what the caller expected.
    #[error("curve ID mismatch: expected {expected:?}, found {found:?}")]
    CurveIdMismatch { expected: CurveId, found: CurveId },

    /// A reserved header byte was non-zero. Readers reject so each circuit
    /// has exactly one canonical `.ar1cs` byte sequence.
    #[error("reserved header byte must be zero")]
    ReservedNotZero,

    #[error("validation failed: {0}")]
    ValidationFailed(String),

    /// Blake3 checksum in the file trailer does not match the computed digest.
    #[error("Blake3 checksum mismatch: file is corrupt")]
    ChecksumMismatch,

    /// File exceeds the maximum allowed size (`MAX_FILE_BYTES`).
    #[error("file exceeds maximum allowed size ({} MB)",
            crate::format::schema::MAX_FILE_BYTES / (1024 * 1024))]
    FileTooLarge,

    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
