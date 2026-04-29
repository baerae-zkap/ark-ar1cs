//! Phase D.5(b) — byte-identical round-trip determinism for `ArcsFile<Fr>`.
//!
//! For every sampled `ArcsFile`:
//!   1. `write` produces `bytes_a`.
//!   2. `read(bytes_a)` reconstructs an `ArcsFile` equal to the original.
//!   3. `write` of the round-tripped instance produces `bytes_b`.
//!   4. `bytes_a == bytes_b` (byte-identical determinism).
//!
//! Runs at ≥1000 iterations under `cargo test --release` (OV-5 #iv).
//! Wall-clock budget: ≤2 minutes / property; observed wall-clock should be
//! orders of magnitude lower because matrices are bounded to ≤16 constraints.

#![cfg(not(target_arch = "wasm32"))]

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_test_fixtures::arb_matrices_with_assignment;
use ark_bn254::Fr;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn arcs_file_write_read_round_trip_is_byte_identical(
        sample in arb_matrices_with_assignment::<Fr>()
    ) {
        let (matrices, _z) = sample;
        let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);

        let mut bytes_a = Vec::new();
        arcs.write(&mut bytes_a).expect("write should not fail");

        let arcs_round_tripped = ArcsFile::<Fr>::read(&mut bytes_a.as_slice())
            .expect("read of just-written bytes should not fail");
        prop_assert_eq!(&arcs_round_tripped, &arcs);

        // Second write must produce identical bytes — `write` is deterministic
        // and the canonical (coeff, var_idx) sort in `write_matrix` makes the
        // result content-addressed.
        let mut bytes_b = Vec::new();
        arcs_round_tripped.write(&mut bytes_b).expect("second write should not fail");
        prop_assert_eq!(bytes_a, bytes_b);
    }
}
