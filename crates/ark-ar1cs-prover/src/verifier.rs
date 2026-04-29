use ark_ar1cs_zkey::ArzkeyFile;
use ark_ec::pairing::Pairing;
use ark_groth16::{prepare_verifying_key, Groth16, Proof};

use crate::error::ProverError;

/// Verify a Groth16 proof against the verifying key embedded in `arzkey` and
/// the explicit `public_inputs` (excluding the implicit `1` wire — arkworks
/// adds it via `pvk.vk.gamma_abc_g1[0]` internally).
///
/// Returns `Ok(true)` for a valid proof, `Ok(false)` for a well-formed proof
/// that fails the pairing check, and `Err(ProverError)` only for genuine
/// framework errors propagated from `ark_groth16` (e.g., a malformed
/// verifying key — which `ArzkeyFile::read` already guards against, so this
/// path is effectively unreachable for files that round-tripped through the
/// envelope).
pub fn verify<E: Pairing>(
    arzkey: &ArzkeyFile<E>,
    public_inputs: &[E::ScalarField],
    proof: &Proof<E>,
) -> Result<bool, ProverError> {
    let pvk = prepare_verifying_key(arzkey.vk());
    let ok = Groth16::<E>::verify_proof(&pvk, proof, public_inputs)?;
    Ok(ok)
}
