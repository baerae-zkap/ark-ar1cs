//! End-to-end closed-loop test: synthesize → setup → wrap → prove → verify.
//!
//! Exercises the full Phase C public surface (`prove` + `verify`) against a
//! real Groth16 setup over the SquareCircuit fixture (`x * x = y`).

mod common;

use ark_ar1cs_prover::{prove, verify};
use ark_bn254::Fr;

use common::{seeded_rng, setup_with_witness};

#[test]
fn closed_loop_synthesize_setup_prove_verify() {
    // x = 3, y = 9 — the canonical valid SquareCircuit instance.
    let (arzkey, arwtns) = setup_with_witness(3);
    let mut rng = seeded_rng();

    let proof = prove(&arzkey, &arwtns, &mut rng).expect("prove() must succeed");
    let ok = verify(&arzkey, &[Fr::from(9u64)], &proof).expect("verify() must not error");
    assert!(ok, "valid proof must verify (Ok(true))");
}

#[test]
fn verify_returns_false_for_wrong_public_input() {
    // Build a real proof for x=3 / y=9, then call verify with a public input
    // that contradicts the witness. The pairing check fails cleanly: verify
    // returns Ok(false), NOT Err. This contract matters for downstream
    // verifiers that distinguish "proof is well-formed but rejects this
    // statement" from "framework-level error".
    let (arzkey, arwtns) = setup_with_witness(3);
    let mut rng = seeded_rng();
    let proof = prove(&arzkey, &arwtns, &mut rng).expect("prove() must succeed");

    let wrong_public = [Fr::from(100u64)];
    let ok = verify(&arzkey, &wrong_public, &proof).expect("verify() must not error");
    assert!(!ok, "wrong public input must produce Ok(false), not Err");
}
