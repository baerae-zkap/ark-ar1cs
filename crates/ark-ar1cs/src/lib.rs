//! Circuit-agnostic Groth16 runtime: portable codecs (.ar1cs, .arzkey)
//! plus prove/verify built on arkworks 0.6.
//!
//! Public surface:
//!   * [`format`] — `.ar1cs` envelope (matrices + header).
//!   * [`arzkey`] — `.arzkey` setup-output (matrices + VK + PK).
//!   * [`prove`] / [`verify`] — Groth16 prover/verifier consuming a parsed
//!     `ArzkeyFile` and a full assignment slice.
//!
//! See `.omc/plans/2026-05-13-stream-1.md` §"PR 1.2" for the crate-fusion
//! history.

#![deny(unsafe_code)]

pub mod arzkey;
pub mod format;

mod preflight;
mod prove;
mod prove_error;
mod verifier;

pub use prove::prove;
pub use prove_error::{ArtifactMismatchReason, ProverError};
pub use verifier::verify;
