//! Circuit-agnostic Groth16 prover/verifier built on `.arzkey` + `.arwtns`.
//!
//! The prover never re-runs the original `ConstraintSynthesizer`. [`prove`]
//! consumes a `(.arzkey, .arwtns)` pair, cross-checks them with
//! [`bind_check`] (cheap→expensive ordering), reconstructs the full
//! assignment via `ArwtnsFile::full_assignment_with_one_wire`, R1CS
//! pre-flights it (OV-1), then hands the matrices and assignment to
//! `Groth16::create_proof_with_reduction_and_matrices`.
//!
//! See `.omc/plans/2026-04-27-sibling-formats-and-prover.md` §4.2 for the
//! public API contract.

#![deny(unsafe_code)]

pub mod bind;
pub mod error;
pub mod preflight;
pub mod verifier;

pub use bind::bind_check;
pub use error::{ArtifactMismatchReason, ProverError};
pub use verifier::verify;

use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof};
use ark_std::rand::{CryptoRng, Rng};

/// Produce a Groth16 proof for `arwtns` against the proving key in `arzkey`.
///
/// Internal sequence (per plan §4.2):
/// 1. [`bind_check`] — four bind rules in cheap→expensive order. Wrong-pair
///    rejection happens here, before any cryptographic work.
/// 2. `arwtns.full_assignment_with_one_wire()` — reconstruct the assignment
///    `z = [F::ONE, instance..., witness...]` arkworks expects.
/// 3. [`preflight::check_r1cs_satisfaction`] — verify `Az[i] * Bz[i] == Cz[i]`
///    for every row (OV-1). Without this, an invalid assignment produces an
///    `Ok(Proof)` that fails verification later.
/// 4. `Groth16::<E>::create_proof_with_reduction_and_matrices` with `r`, `s`
///    sampled from `rng`.
pub fn prove<E, R>(
    arzkey: &ArzkeyFile<E>,
    arwtns: &ArwtnsFile<E::ScalarField>,
    rng: &mut R,
) -> Result<Proof<E>, ProverError>
where
    E: Pairing,
    R: Rng + CryptoRng,
{
    bind_check(arzkey, arwtns)?;

    let full_assignment = arwtns.full_assignment_with_one_wire();
    preflight::check_r1cs_satisfaction(arzkey.arcs(), &full_assignment)?;

    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    // `into_matrices` consumes its receiver; clone the embedded ArcsFile so
    // arzkey itself stays intact for the caller (and for verify() later).
    let matrices = arzkey.arcs().clone().into_matrices();

    let proof = Groth16::<E>::create_proof_with_reduction_and_matrices(
        arzkey.pk(),
        r,
        s,
        &matrices,
        arzkey.header.num_instance_variables as usize,
        arzkey.header.num_constraints as usize,
        &full_assignment,
    )?;
    Ok(proof)
}
