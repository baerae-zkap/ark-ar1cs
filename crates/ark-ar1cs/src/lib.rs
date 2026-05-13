//! Circuit-agnostic Groth16 runtime: portable codecs (.ar1cs, .arzkey)
//! plus prove/verify built on arkworks 0.6.
//!
//! Public surface:
//!   * [`format`] — `.ar1cs` envelope (matrices + header).
//!   * [`arzkey`] — `.arzkey` setup-output (matrices + VK + PK).
//!   * [`prove`] / [`verify`] — Groth16 prover/verifier consuming a parsed
//!     `ArzkeyFile` and a full assignment slice.
//!
//! ## Caller-side binding (recommended pattern)
//!
//! As of Stream 1, [`prove`] does not perform `ar1cs_blake3` binding
//! automatically; callers compare the arzkey's circuit identity hash against
//! a known-good value (deployment manifest, on-chain registry, etc.) before
//! invoking `prove`:
//!
//! ```rust,ignore
//! if arzkey.header.ar1cs_blake3 != expected_ar1cs_blake3 {
//!     return Err(ProverError::ArtifactMismatch {
//!         reason: ArtifactMismatchReason::Ar1csBlake3,
//!     });
//! }
//! let proof = ark_ar1cs::prove(&arzkey, &full_assignment, &mut rng)?;
//! ```
//!
//! The remaining historical bind rules are auto-guaranteed elsewhere:
//! `curve_id` by `ArzkeyFile::<E>::read`, body-hash self-consistency by
//! `ArcsFile::read`, and instance/witness count by `prove`'s automatic
//! [`ProverError::WitnessLengthMismatch`].
//!
//! See `.omc/plans/2026-05-13-stream-1.md` §"PR 1.2" for the crate-fusion
//! history.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod arzkey;
pub mod format;
pub mod witness;

mod preflight;
mod prove;
mod prove_error;
mod verifier;

pub use prove::prove;
pub use prove_error::{ArtifactMismatchReason, ProverError};
pub use verifier::verify;
pub use witness::{synthesize_full_assignment, WitnessError};
