use std::fmt;

use crate::header::CurveId;

#[derive(Debug)]
pub enum ArcsError {
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedCurve(u8),
    /// The file's curve ID doesn't match what the caller expected.
    CurveIdMismatch { expected: CurveId, found: CurveId },
    ValidationFailed(String),
    /// Blake3 checksum in the file trailer does not match the computed digest.
    ChecksumMismatch,
    /// File exceeds the maximum allowed size (`MAX_FILE_BYTES`).
    FileTooLarge,
    Serialization(ark_serialize::SerializationError),
    Io(std::io::Error),
}

impl fmt::Display for ArcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArcsError::InvalidMagic => write!(f, "invalid magic bytes"),
            ArcsError::UnsupportedVersion(v) => write!(f, "unsupported version: {v:#x}"),
            ArcsError::UnsupportedCurve(c) => write!(f, "unsupported curve ID: {c:#x}"),
            ArcsError::CurveIdMismatch { expected, found } => {
                write!(f, "curve ID mismatch: expected {expected:?}, found {found:?}")
            }
            ArcsError::ValidationFailed(msg) => write!(f, "validation failed: {msg}"),
            ArcsError::ChecksumMismatch => write!(f, "Blake3 checksum mismatch: file is corrupt"),
            ArcsError::FileTooLarge => write!(
                f,
                "file exceeds maximum allowed size ({} MB)",
                crate::schema::MAX_FILE_BYTES / (1024 * 1024)
            ),
            ArcsError::Serialization(e) => write!(f, "serialization error: {e}"),
            ArcsError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ArcsError {}

impl From<std::io::Error> for ArcsError {
    fn from(e: std::io::Error) -> Self {
        ArcsError::Io(e)
    }
}

impl From<ark_serialize::SerializationError> for ArcsError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        ArcsError::Serialization(e)
    }
}
