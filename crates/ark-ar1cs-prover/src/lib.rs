//! Circuit-agnostic Groth16 prover/verifier built on `.arzkey` + `.arwtns`.
//!
//! The prover never re-runs the original `ConstraintSynthesizer` — `prove()`
//! consumes a `(.arzkey, .arwtns)` pair, cross-checks them with [`bind_check`]
//! (cheap→expensive ordering), reconstructs the full assignment via
//! `ArwtnsFile::full_assignment_with_one_wire`, R1CS pre-flights it (OV-1),
//! and hands it to `Groth16::create_proof_with_reduction_and_matrices`.
//!
//! See `.omc/plans/2026-04-27-sibling-formats-and-prover.md` §4.2 for the
//! public API contract.

#![deny(unsafe_code)]

pub mod bind;
pub mod error;

pub use bind::bind_check;
pub use error::{ArtifactMismatchReason, ProverError};
