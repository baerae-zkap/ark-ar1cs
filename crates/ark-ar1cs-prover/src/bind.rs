use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_ec::pairing::Pairing;

use crate::error::{ArtifactMismatchReason, ProverError};

/// Cross-validate that `arzkey` and `arwtns` describe the same circuit.
///
/// The four bind rules (`§3.3` of the plan) execute in cheap→expensive order
/// so a wrong artifact is rejected with `O(1)` work whenever possible. The
/// expensive `O(ar1cs_byte_len)` self-consistency hash check (rule 3) only
/// fires after all three `O(1)` rules pass. This split corresponds to the
/// PERF-1 §5a/§5b latency budgets.
///
/// Trailer integrity is NOT re-checked here — both [`ArzkeyFile::read`] and
/// [`ArwtnsFile::read`] have already verified their respective Blake3
/// trailers at parse time, so re-hashing the file body here would be a
/// redundant `O(file_size)` pass.
pub fn bind_check<E: Pairing>(
    arzkey: &ArzkeyFile<E>,
    arwtns: &ArwtnsFile<E::ScalarField>,
) -> Result<(), ProverError> {
    // Rule 1 — header curve_id (O(1)).
    let arz_cid = arzkey.header.curve_id as u8;
    let arw_cid = arwtns.header.curve_id as u8;
    if arz_cid != arw_cid {
        return Err(ProverError::ArtifactMismatch {
            reason: ArtifactMismatchReason::CurveId {
                arzkey: arz_cid,
                arwtns: arw_cid,
            },
        });
    }

    // Rule 2 — circuit identity hash compare (O(1) 32-byte memcmp).
    if arzkey.header.ar1cs_blake3 != arwtns.header.ar1cs_blake3 {
        return Err(ProverError::ArtifactMismatch {
            reason: ArtifactMismatchReason::Ar1csBlake3,
        });
    }

    // Rule 4 — instance/witness count sum (O(1)).
    //
    // `arwtns` body excludes the implicit "1" wire (variable index 0) so
    // num_instance + num_witness must equal
    // (arzkey.num_instance_variables - 1) + arzkey.num_witness_variables.
    // ArcsFile::validate guarantees num_instance_variables >= 1, so the
    // saturating_sub never underflows in practice.
    let expected = arzkey
        .header
        .num_instance_variables
        .saturating_sub(1)
        .saturating_add(arzkey.header.num_witness_variables);
    let got = arwtns
        .header
        .num_instance
        .saturating_add(arwtns.header.num_witness);
    if expected != got {
        return Err(ProverError::ArtifactMismatch {
            reason: ArtifactMismatchReason::CountMismatch { expected, got },
        });
    }

    // Rule 3 — `.arzkey` self-consistency (O(ar1cs_byte_len), runs LAST).
    //
    // `ArzkeyFile::read` already enforces this at parse time. The check is
    // repeated here so prove() callers who construct an `ArzkeyFile` via
    // `from_setup_output` followed by manual header mutation cannot bypass
    // it. For load-from-disk callers this branch is a paid-once tautology;
    // the cost is dwarfed by the Groth16 itself.
    if arzkey.arcs().body_blake3() != arzkey.header.ar1cs_blake3 {
        return Err(ProverError::ArtifactMismatch {
            reason: ArtifactMismatchReason::SelfConsistency,
        });
    }

    Ok(())
}
