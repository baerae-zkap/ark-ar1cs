//! Phase D.5(b) — byte-identical round-trip determinism for `ArwtnsFile<Fr>`.
//!
//! For every sampled `ArwtnsFile`:
//!   1. `write` produces `bytes_a`.
//!   2. `read(bytes_a)` reconstructs an `ArwtnsFile` equal to the original.
//!   3. `write` of the round-tripped instance produces `bytes_b`.
//!   4. `bytes_a == bytes_b` (byte-identical determinism).
//!
//! Runs at ≥1000 iterations under `cargo test --release` (OV-5 #iv).
//! Reuses the bounded `arb_matrices_with_assignment` strategy from
//! `ark_ar1cs_format::test_fixtures`: `z = [F::ONE, instance..., witness...]`
//! is split into `(instance, witness)` so the witness vector lengths follow
//! the same hard bounds as the format/prover proptests.

#![cfg(not(target_arch = "wasm32"))]

use ark_ar1cs_format::test_fixtures::arb_matrices_with_assignment;
use ark_ar1cs_format::CurveId;
use ark_ar1cs_wtns::ArwtnsFile;
use ark_bn254::Fr;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn arwtns_file_write_read_round_trip_is_byte_identical(
        sample in arb_matrices_with_assignment::<Fr>(),
        ar1cs_blake3 in prop::array::uniform32(any::<u8>()),
    ) {
        let (matrices, z) = sample;
        // z = [F::ONE, instance..., witness...]. Strip the implicit "1" wire;
        // ArwtnsFile::from_assignments expects explicit instance + witness.
        let n_inst_explicit = matrices.num_instance_variables - 1;
        let instance: Vec<Fr> = z[1..1 + n_inst_explicit].to_vec();
        let witness: Vec<Fr> = z[1 + n_inst_explicit..].to_vec();

        let wtns = ArwtnsFile::<Fr>::from_assignments(
            CurveId::Bn254,
            ar1cs_blake3,
            &instance,
            &witness,
        );

        let mut bytes_a = Vec::new();
        wtns.write(&mut bytes_a).expect("write should not fail");

        let round_tripped = ArwtnsFile::<Fr>::read(&mut bytes_a.as_slice())
            .expect("read of just-written bytes should not fail");
        prop_assert_eq!(&round_tripped, &wtns);

        let mut bytes_b = Vec::new();
        round_tripped.write(&mut bytes_b).expect("second write should not fail");
        prop_assert_eq!(bytes_a, bytes_b);
    }
}
