#![deny(unsafe_code)]

pub mod error;
pub mod header;
pub mod schema;

pub use error::ArwtnsError;
pub use header::{ArwtnsHeader, ARWTNS_HEADER_SIZE, ARWTNS_MAGIC, ARWTNS_VERSION_V0};
pub use schema::{ArwtnsFile, MAX_ARWTNS_BYTES};
