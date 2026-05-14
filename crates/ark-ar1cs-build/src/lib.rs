//! Build-time toolchain for ark-ar1cs: `ConstraintSynthesizer` → `.ar1cs`.
//!
//! Runtime concerns (`prove`, codec read paths, the `witness` helper)
//! live in `ark-ar1cs`. This crate hosts the *write-side* helper that
//! consumes an arkworks `ConstraintSynthesizer` and produces a portable
//! `.ar1cs` artifact via [`export_circuit`].
//!
//! Earlier revisions also shipped a `from_setup_output` helper that
//! bundled `(ArcsFile, ProvingKey)` into a single `.arzkey` envelope.
//! The feature-boundary migration removes that envelope: deployments
//! distribute the `.ar1cs` body and the proving key separately (via
//! arkworks `CanonicalSerialize`) and bind them out of band through a
//! manifest. See `docs/artifact-trust-boundary.md` for the boundary
//! rationale.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod exporter;

pub use exporter::{export_circuit, ExportError};
