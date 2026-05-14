//! Circuit-agnostic Groth16 prover.
//!
//! [`prove`] consumes a separately-held [`ProvingKey`], a parsed
//! [`ArcsFile`] (i.e. the `.ar1cs` byte body deserialized), and a
//! pre-built full assignment vector `[F::ONE, instance..., witness...]`.
//! It runs the mandatory R1CS pre-flight against the matrices in `arcs`,
//! then forwards to
//! `Groth16::create_proof_with_reduction_and_matrices`. The original
//! `ConstraintSynthesizer` is never re-run.
//!
//! ## Identity binding is the caller's responsibility
//!
//! `prove` performs **no** identity comparison between `pk` and `arcs` —
//! no `ar1cs_blake3` check, no manifest lookup, no expected-hash argument.
//! Two trusted setups for the same `.ar1cs` produce *different* `(pk, vk)`,
//! and `prove` cannot tell the deployment's intended pair apart from any
//! other `pk` of the right curve. Identity binding lives in the
//! deployment manifest:
//!
//! ```ignore
//! if arcs.body_blake3() != manifest.expected_ar1cs_blake3 {
//!     return Err(MyCallerError::WrongCircuitArtifact);
//! }
//! let proof = ark_ar1cs::prove(&pk, &arcs, &full_assignment, &mut rng)?;
//! ```
//!
//! See `docs/artifact-trust-boundary.md` for the full rationale.
//!
//! ## Type-level curve invariant
//!
//! `pk: &ProvingKey<E>` and `arcs: &ArcsFile<E::ScalarField>` share the
//! type parameter `E`, so a `ProvingKey<Bn254>` cannot be passed alongside
//! `ArcsFile<<Bls12_381 as Pairing>::ScalarField>` — a curve mismatch is
//! a compile error, not a runtime arm.

use crate::format::ArcsFile;
use crate::preflight;
use crate::prove_error::ProverError;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_std::rand::{CryptoRng, Rng};

/// Produce a Groth16 proof for `full_assignment` against `pk` and `arcs`.
///
/// Internal sequence:
/// 1. Length check — [`ProverError::WitnessLengthMismatch`] if
///    `full_assignment.len() != arcs.header.num_instance_variables +
///    arcs.header.num_witness_variables`.
/// 2. R1CS pre-flight — [`crate::ProverError::AssignmentNotSatisfying`]
///    if `Az[i] * Bz[i] != Cz[i]` at the indicated row. Without this
///    check `Groth16::create_proof_with_reduction_and_matrices` would
///    return an `Ok(Proof)` that always fails verification — the worst
///    footgun in a SNARK toolkit.
/// 3. `Groth16::<E>::create_proof_with_reduction_and_matrices` with `r`,
///    `s` sampled from `rng`.
///
/// `full_assignment` MUST be `[F::ONE, instance..., witness...]` — the
/// layout produced by [`crate::synthesize_full_assignment`] (or
/// equivalent caller logic).
pub fn prove<E, R>(
    pk: &ProvingKey<E>,
    arcs: &ArcsFile<E::ScalarField>,
    full_assignment: &[E::ScalarField],
    rng: &mut R,
) -> Result<Proof<E>, ProverError>
where
    E: Pairing,
    R: Rng + CryptoRng,
{
    let expected_len =
        (arcs.header.num_instance_variables + arcs.header.num_witness_variables) as usize;
    if full_assignment.len() != expected_len {
        return Err(ProverError::WitnessLengthMismatch {
            expected: expected_len,
            got: full_assignment.len(),
        });
    }

    preflight::check_r1cs_satisfaction(arcs, full_assignment)?;

    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    let matrices = [arcs.a.clone(), arcs.b.clone(), arcs.c.clone()];

    let proof = Groth16::<E>::create_proof_with_reduction_and_matrices(
        pk,
        r,
        s,
        &matrices,
        arcs.header.num_instance_variables as usize,
        arcs.header.num_constraints as usize,
        full_assignment,
    )?;
    Ok(proof)
}
