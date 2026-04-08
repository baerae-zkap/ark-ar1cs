use std::fmt;

#[derive(Debug)]
pub enum ArcsError {
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedCurve(u8),
    ValidationFailed(String),
    Serialization(ark_serialize::SerializationError),
    Io(std::io::Error),
}

impl fmt::Display for ArcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArcsError::InvalidMagic => write!(f, "invalid magic bytes"),
            ArcsError::UnsupportedVersion(v) => write!(f, "unsupported version: {v:#x}"),
            ArcsError::UnsupportedCurve(c) => write!(f, "unsupported curve ID: {c:#x}"),
            ArcsError::ValidationFailed(msg) => write!(f, "validation failed: {msg}"),
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
