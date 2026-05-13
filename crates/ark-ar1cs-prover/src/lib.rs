//! Circuit-agnostic Groth16 prover/verifier built on `.arzkey`.
//!
//! The prover never re-runs the original `ConstraintSynthesizer`. [`prove`]
//! consumes an `.arzkey` and a pre-built full assignment vector
//! `[F::ONE, instance..., witness...]`, R1CS pre-flights it (OV-1), then
//! hands the matrices and assignment to
//! `Groth16::create_proof_with_reduction_and_matrices`.
//!
//! Header binding (e.g. comparing `arzkey.header.ar1cs_blake3` against an
//! expected circuit identity) is **the caller's** one-line responsibility —
//! the prover no longer wires this automatically. The
//! [`ProverError::ArtifactMismatch`] / [`ArtifactMismatchReason`] types are
//! retained for callers that want a structured error in that one-line check.
//!
//! See `.omc/plans/2026-05-13-stream-1.md` §"PR 1.0" for the public API
//! contract.

#![deny(unsafe_code)]

pub mod error;
pub mod preflight;
pub mod verifier;

pub use error::{ArtifactMismatchReason, ProverError};
pub use verifier::verify;

use ark_ar1cs_zkey::ArzkeyFile;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof};
use ark_std::rand::{CryptoRng, Rng};

/// Produce a Groth16 proof for `full_assignment` against the proving key in
/// `arzkey`.
///
/// `full_assignment` MUST be `[F::ONE, instance..., witness...]` and have
/// length `arzkey.header.num_instance_variables +
/// arzkey.header.num_witness_variables`. Mismatched lengths surface
/// [`ProverError::WitnessLengthMismatch`].
///
/// Internal sequence (per plan §1.0.1):
/// 1. Length check (`WitnessLengthMismatch`).
/// 2. [`preflight::check_r1cs_satisfaction`] — verify `Az[i] * Bz[i] == Cz[i]`
///    for every row (OV-1). Without this, an invalid assignment produces an
///    `Ok(Proof)` that fails verification later.
/// 3. `Groth16::<E>::create_proof_with_reduction_and_matrices` with `r`, `s`
///    sampled from `rng`.
///
/// Header binding (curve / circuit identity) is **not** performed here —
/// `ArzkeyFile::<E>::read` already rejects wrong-curve artifacts at parse
/// time, and `ar1cs_blake3` comparison is the caller's one-line check:
///
/// ```ignore
/// if arzkey.header.ar1cs_blake3 != expected_ar1cs_blake3 {
///     return Err(ProverError::ArtifactMismatch {
///         reason: ArtifactMismatchReason::Ar1csBlake3,
///     });
/// }
/// prove(&arzkey, &full_assignment, &mut rng)?;
/// ```
pub fn prove<E, R>(
    arzkey: &ArzkeyFile<E>,
    full_assignment: &[E::ScalarField],
    rng: &mut R,
) -> Result<Proof<E>, ProverError>
where
    E: Pairing,
    R: Rng + CryptoRng,
{
    let expected_len =
        (arzkey.header.num_instance_variables + arzkey.header.num_witness_variables) as usize;
    if full_assignment.len() != expected_len {
        return Err(ProverError::WitnessLengthMismatch {
            expected: expected_len,
            got: full_assignment.len(),
        });
    }

    preflight::check_r1cs_satisfaction(arzkey.arcs(), full_assignment)?;

    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    // `into_matrices` consumes its receiver; clone the embedded ArcsFile so
    // arzkey itself stays intact for the caller (and for verify() later).
    let matrices = arzkey.arcs().clone().into_matrices();

    let proof = Groth16::<E>::create_proof_with_reduction_and_matrices(
        arzkey.pk(),
        r,
        s,
        &[matrices.a, matrices.b, matrices.c],
        arzkey.header.num_instance_variables as usize,
        arzkey.header.num_constraints as usize,
        full_assignment,
    )?;
    Ok(proof)
}
