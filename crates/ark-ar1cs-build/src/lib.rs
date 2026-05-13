//! Build-time toolchain for ark-ar1cs: Circuit → .ar1cs + .arzkey.
//!
//! Runtime concerns (`prove`, `verify`, codec read paths) live in `ark-ar1cs`.
//! This crate hosts the *write-side* helpers that consume an arkworks
//! `ConstraintSynthesizer` and produce the deployable artifacts.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod exporter;
pub mod setup;

pub use exporter::{export_circuit, ExportError};
pub use setup::from_setup_output;
