//! Generator self-test (Phase D.5 prep).
//!
//! Validates that every `(matrices, full_assignment)` pair sampled from
//! [`arb_matrices_with_assignment`] satisfies the R1CS relation
//! `Az[i]·Bz[i] == Cz[i]` for every row, and respects the OV-5 #iv bounds
//! (≤16 constraints, ≤64 non-zeros per matrix).
//!
//! Per `prove-must-preflight-r1cs` (10/10): a buggy generator that emits
//! non-satisfying samples would fire `ProverError::AssignmentNotSatisfying`
//! in the downstream Phase D.5(a) `prove → verify` property test, polluting
//! its signal. Catching the issue here keeps that downstream test clean.
//!
//! Runs at ≥1000 iterations under `cargo test --release`.

#![cfg(not(target_arch = "wasm32"))]

use ark_ar1cs_format::test_fixtures::{
    arb_matrices_with_assignment, PROPTEST_MAX_CONSTRAINTS, PROPTEST_MAX_NONZEROS_PER_MATRIX,
};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use proptest::prelude::*;

fn dot(row: &[(Fr, usize)], z: &[Fr]) -> Fr {
    let mut acc = Fr::ZERO;
    for (c, idx) in row {
        acc += *c * z[*idx];
    }
    acc
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        // Wide failure shrinking is unnecessary here — the generator is the
        // unit under test, not external input. Keep shrink iterations modest
        // so a single bad sample doesn't blow the wall-clock budget.
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    /// Every sampled `(matrices, full_assignment)` pair satisfies R1CS row by
    /// row (and respects the OV-5 #iv hard bounds).
    #[test]
    fn generator_always_satisfies_r1cs(
        sample in arb_matrices_with_assignment::<Fr>()
    ) {
        let (matrices, z) = sample;

        prop_assert!(matrices.num_constraints >= 1);
        prop_assert!(matrices.num_constraints <= PROPTEST_MAX_CONSTRAINTS);
        prop_assert!(matrices.a_num_non_zero <= PROPTEST_MAX_NONZEROS_PER_MATRIX);
        prop_assert!(matrices.b_num_non_zero <= PROPTEST_MAX_NONZEROS_PER_MATRIX);
        prop_assert!(matrices.c_num_non_zero <= PROPTEST_MAX_NONZEROS_PER_MATRIX);

        // ArcsFile::validate() invariants (mirrored here so a generator drift
        // surfaces as a self-test failure rather than as a parse-time error
        // downstream).
        prop_assert!(matrices.num_instance_variables >= 1);
        let total_vars = matrices.num_instance_variables + matrices.num_witness_variables;
        prop_assert_eq!(z.len(), total_vars);
        prop_assert_eq!(z[0], Fr::ONE);

        for (i, ((a_row, b_row), c_row)) in matrices
            .a
            .iter()
            .zip(matrices.b.iter())
            .zip(matrices.c.iter())
            .enumerate()
        {
            let az = dot(a_row, &z);
            let bz = dot(b_row, &z);
            let cz = dot(c_row, &z);
            prop_assert_eq!(az * bz, cz, "row {} not R1CS-satisfying", i);
        }
    }
}
