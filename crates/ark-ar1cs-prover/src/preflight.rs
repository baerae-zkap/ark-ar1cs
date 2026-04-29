use ark_ar1cs_format::ArcsFile;
use ark_ff::PrimeField;

use crate::error::ProverError;

/// Verify the R1CS satisfaction relation `Az[i] * Bz[i] == Cz[i]` for every
/// row `i` of the constraint system encoded in `arcs`, given the full
/// assignment vector `z = [F::ONE, instance..., witness...]`.
///
/// This is the **mandatory** OV-1 pre-flight. `Groth16::create_proof_with_
/// reduction_and_matrices` does NOT verify R1CS satisfaction itself; without
/// this check an invalid assignment produces an `Ok(Proof)` that always fails
/// verification — the worst kind of footgun in a SNARK toolkit. Returning
/// [`ProverError::AssignmentNotSatisfying`] here makes the failure loud and
/// localizable to a specific constraint row.
///
/// Cost is `O(sum of matrix nonzeros)`, dwarfed by the Groth16 MSM that
/// follows on a valid assignment.
pub fn check_r1cs_satisfaction<F: PrimeField>(
    arcs: &ArcsFile<F>,
    full_assignment: &[F],
) -> Result<(), ProverError> {
    let expected_len = (arcs.header.num_instance_variables
        + arcs.header.num_witness_variables) as usize;
    if full_assignment.len() != expected_len {
        return Err(ProverError::WitnessLengthMismatch {
            expected: expected_len,
            got: full_assignment.len(),
        });
    }

    // Sparse dot product of one R1CS matrix row against the full assignment.
    // var_idx is bounds-checked structurally by ArcsFile::validate (which
    // ArcsFile::read runs), so direct indexing is safe here.
    let dot = |row: &[(F, usize)]| -> F {
        let mut acc = F::ZERO;
        for (coeff, var_idx) in row {
            acc += *coeff * full_assignment[*var_idx];
        }
        acc
    };

    for (i, ((a_row, b_row), c_row)) in arcs
        .a
        .iter()
        .zip(arcs.b.iter())
        .zip(arcs.c.iter())
        .enumerate()
    {
        let az = dot(a_row);
        let bz = dot(b_row);
        let cz = dot(c_row);
        if az * bz != cz {
            return Err(ProverError::AssignmentNotSatisfying { row: i });
        }
    }
    Ok(())
}
