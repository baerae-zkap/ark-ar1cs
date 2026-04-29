//! End-to-end test: synthesize → setup → wrap → prove → verify.
//!
//! Commit 3 ships the happy path with a direct
//! `Groth16::verify_proof(prepare_verifying_key(arzkey.vk()), ...)` call;
//! the prover-crate `verify()` helper arrives in Commit 4.

mod common;

use ark_ar1cs_prover::prove;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16};

use common::{seeded_rng, setup_with_witness};

#[test]
fn happy_path_prove_then_verify_direct() {
    // x = 3, y = 9 — a valid SquareCircuit instance.
    let (arzkey, arwtns) = setup_with_witness(3);

    let mut rng = seeded_rng();
    let proof = prove(&arzkey, &arwtns, &mut rng).expect("prove() must succeed");

    let pvk = prepare_verifying_key(arzkey.vk());
    let public_inputs = [Fr::from(9u64)];
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .expect("verify_proof must not error");
    assert!(ok, "Groth16 must accept a proof produced from a valid assignment");
}
