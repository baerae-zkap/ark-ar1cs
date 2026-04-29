#![deny(unsafe_code)]

pub mod error;
pub mod exporter;
pub mod header;
pub mod importer;
pub mod matrix;
pub mod schema;

#[cfg(feature = "test-fixtures")]
pub mod test_fixtures;

pub use error::ArcsError;
pub use header::{ArcsHeader, CurveId, MAGIC, VERSION_V0};
pub use matrix::Matrix;
pub use schema::{ArcsFile, MAX_FILE_BYTES};
