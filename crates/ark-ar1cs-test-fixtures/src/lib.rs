//! Test fixtures shared across the ark-ar1cs workspace.
//!
//! - [`make_test_matrices`] — deterministic 3-constraint BN254 R1CS used by
//!   the negative-test suites in `format`, `wtns`, and `zkey`.
//! - [`arb_matrices_with_assignment`] — bounded `proptest` strategy that
//!   yields R1CS-satisfying `(matrices, full_assignment)` pairs by
//!   construction, used by the Phase D property tests in `format`, `wtns`,
//!   and `prover`. Native-only (gated `cfg(not(target_arch = "wasm32"))`)
//!   so the crate's wasm32 build stays clean per OV-4.

#[cfg(not(target_arch = "wasm32"))]
mod proptest_gen;
#[cfg(not(target_arch = "wasm32"))]
pub use proptest_gen::{
    arb_matrices_with_assignment, MatricesWithAssignment, PROPTEST_MAX_CONSTRAINTS,
    PROPTEST_MAX_NONZEROS_PER_MATRIX,
};

/// Shared test fixture: 3-constraint R1CS for BN254.
///
/// Variables: [1(implicit), x(pub), w1(witness), w2(witness)]
///   num_instance_variables = 2 (includes implicit "1" wire)
///   num_witness_variables  = 2
///   num_constraints        = 3
///
/// Constraint semantics:
///   A[0] * B[0] = C[0]  →  x  * 1  = x
///   A[1] * B[1] = C[1]  →  w1 * 1  = w1
///   A[2] * B[2] = C[2]  →  w2 * x  = w1
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintMatrices;

pub fn make_test_matrices() -> ConstraintMatrices<Fr> {
    let a = vec![
        vec![(Fr::from(1u64), 1)], // row 0: 1*x
        vec![(Fr::from(1u64), 2)], // row 1: 1*w1
        vec![(Fr::from(1u64), 3)], // row 2: 1*w2
    ];
    let b = vec![
        vec![(Fr::from(1u64), 0)], // row 0: 1*"1"
        vec![(Fr::from(1u64), 0)], // row 1: 1*"1"
        vec![(Fr::from(1u64), 1)], // row 2: 1*x
    ];
    let c = vec![
        vec![(Fr::from(1u64), 1)], // row 0: 1*x
        vec![(Fr::from(1u64), 2)], // row 1: 1*w1
        vec![(Fr::from(1u64), 2)], // row 2: 1*w1
    ];
    ConstraintMatrices {
        num_instance_variables: 2,
        num_witness_variables: 2,
        num_constraints: 3,
        a_num_non_zero: 3,
        b_num_non_zero: 3,
        c_num_non_zero: 3,
        a,
        b,
        c,
    }
}
