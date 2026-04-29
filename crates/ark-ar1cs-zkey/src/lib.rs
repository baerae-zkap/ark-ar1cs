#![deny(unsafe_code)]

pub mod error;
pub mod header;
pub mod schema;

pub use error::ArzkeyError;
pub use header::{ArzkeyHeader, ARZKEY_HEADER_SIZE, ARZKEY_MAGIC, ARZKEY_VERSION_V0};
pub use schema::{ArzkeyFile, MAX_ARZKEY_BYTES};
