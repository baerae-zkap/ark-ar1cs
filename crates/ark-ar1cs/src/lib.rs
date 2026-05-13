//! Circuit-agnostic Groth16 runtime: portable codecs (.ar1cs, .arzkey)
//! plus prove/verify built on arkworks 0.6.
//!
//! Public surface:
//!   * [`format`] — `.ar1cs` envelope (matrices + header).
//!   * [`witness`] — generic `ConstraintSynthesizer → Vec<F>` helper
//!     ([`synthesize_full_assignment`] / [`WitnessError`], also
//!     re-exported at crate root).
//!   * [`arzkey`] — `.arzkey` setup-output (matrices + VK + PK).
//!     Removed in a later commit of the feature-boundary migration;
//!     transitional today.
//!   * [`prove`] / [`verify`] — Groth16 prover and verifier wrapper.
//!     `prove` takes `(&ProvingKey<E>, &ArcsFile<E::ScalarField>,
//!     &[E::ScalarField], &mut R)` and runs a length + R1CS preflight
//!     before forwarding to `Groth16::create_proof_with_reduction_and_matrices`.
//!
//! ## Caller-side binding (recommended pattern)
//!
//! [`prove`] does not bind circuit identity inside the call. Callers
//! compare the parsed `.ar1cs` body hash against a known-good value
//! (deployment manifest, on-chain registry, etc.) before invoking
//! `prove`:
//!
//! ```rust,ignore
//! if arcs.body_blake3() != manifest.expected_ar1cs_blake3 {
//!     return Err(MyCallerError::WrongCircuitArtifact);
//! }
//! let proof = ark_ar1cs::prove(&pk, &arcs, &full_assignment, &mut rng)?;
//! ```
//!
//! Curve agreement between `pk` and `arcs` is enforced at the type
//! level (both carry the same `E`). Body-hash self-consistency is
//! verified by `ArcsFile::read`. Witness length is checked by `prove`
//! and surfaces as [`ProverError::WitnessLengthMismatch`].
//!
//! See `docs/artifact-trust-boundary.md` for the boundary rationale.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod arzkey;
pub mod format;
pub mod witness;

mod preflight;
mod prove;
mod prove_error;
mod verifier;

pub use prove::prove;
pub use prove_error::ProverError;
pub use verifier::verify;
pub use witness::{synthesize_full_assignment, WitnessError};
