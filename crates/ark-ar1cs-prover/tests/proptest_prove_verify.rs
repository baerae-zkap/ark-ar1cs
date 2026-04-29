//! Phase D.5(a) — for any R1CS-satisfying assignment, `prove → verify`
//! returns `Ok(true)`.
//!
//! Per `prove-must-preflight-r1cs` (10/10): an `Ok(Proof)` that fails verify
//! is the worst kind of footgun in a SNARK toolkit, so this property is the
//! structural validation that the OV-1 R1CS pre-flight + Groth16 wiring
//! together hold for every valid witness across the OV-5 #iv generator
//! bound (≤16 constraints, ≤64 non-zeros).
//!
//! The matrices are fed to `Groth16::generate_random_parameters_with_reduction`
//! through [`ImportedCircuit`] — exactly the production setup path that
//! consumers (zkap-zkp, etc.) follow — so this test also validates the
//! `.ar1cs → ImportedCircuit → setup → from_setup_output → prove → verify`
//! pipeline end-to-end.
//!
//! Runs at ≥1000 iterations under `cargo test --release` (OV-5 #iv).
//! Wall-clock budget: ≤2 minutes / property; observed wall-clock should sit
//! around tens of seconds because Groth16 setup dominates and matrices are
//! capped at 16 constraints.

#![cfg(not(target_arch = "wasm32"))]

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_importer::ImportedCircuit;
use ark_ar1cs_prover::{prove, verify};
use ark_ar1cs_test_fixtures::arb_matrices_with_assignment;
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_satisfying_assignment_proves_and_verifies(
        sample in arb_matrices_with_assignment::<Fr>(),
        rng_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let (matrices, z) = sample;

        // Split z = [F::ONE, instance..., witness...] back into the explicit
        // (instance, witness) tuple that ArwtnsFile::from_assignments expects
        // (the implicit "1" wire is reconstructed by
        // full_assignment_with_one_wire() inside prove()).
        let n_inst_explicit = matrices.num_instance_variables - 1;
        let instance: Vec<Fr> = z[1..1 + n_inst_explicit].to_vec();
        let witness: Vec<Fr> = z[1 + n_inst_explicit..].to_vec();

        // Build .ar1cs and feed it to Groth16 setup via ImportedCircuit —
        // mirrors the production export → setup path so the test exercises
        // the same byte boundaries that real consumers cross.
        let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);
        let ar1cs_blake3 = arcs.body_blake3();

        let mut arcs_bytes = Vec::new();
        arcs.write(&mut arcs_bytes).expect("ArcsFile::write should not fail");
        let circuit = ImportedCircuit::<Fr>::from_reader(
            &mut arcs_bytes.as_slice(),
            CurveId::Bn254,
        )
        .expect("ImportedCircuit::from_reader on just-written bytes should not fail");

        let mut rng = StdRng::from_seed(rng_seed);
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .expect("Groth16 setup should not fail for bounded R1CS-valid matrices");

        let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);
        let arwtns = ArwtnsFile::<Fr>::from_assignments(
            CurveId::Bn254,
            ar1cs_blake3,
            &instance,
            &witness,
        );

        let proof = prove(&arzkey, &arwtns, &mut rng)
            .expect("prove() must not fail on a generator-guaranteed valid assignment");
        let ok = verify(&arzkey, &instance, &proof)
            .expect("verify() must not error on a well-formed proof");
        prop_assert!(ok, "Groth16 verify must accept a proof of a valid assignment");
    }
}
