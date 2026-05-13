//! Portable `.arzkey` setup-output (matrices + VK + PK).
//!
//! Re-exported under `ark_ar1cs::arzkey::*`.

pub mod error;
pub mod header;
pub mod schema;

pub use error::ArzkeyError;
pub use header::{
    ArzkeyHeader, ARZKEY_HEADER_SIZE, ARZKEY_MAGIC, ARZKEY_VERSION_CURRENT, ARZKEY_VERSION_V0,
    ARZKEY_VERSION_V1,
};
pub use schema::{ArzkeyFile, MAX_ARZKEY_BYTES};
