#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end closed-loop test: synthesize → setup → prove → verify.
//!
//! Exercises the full post-migration prove path against a real Groth16
//! setup over the SquareCircuit fixture (`x * x = y`). Verify is one
//! line of arkworks — `ark_ar1cs::verify` no longer exists.

mod common;

use ark_ar1cs::prove;
use ark_bn254::Fr;
use ark_groth16::{prepare_verifying_key, Groth16};

use common::{seeded_rng, setup_with_witness};

#[test]
fn closed_loop_synthesize_setup_prove_verify() {
    // x = 3, y = 9 — the canonical valid SquareCircuit instance.
    let (pk, arcs, full_assignment) = setup_with_witness(3);
    let mut rng = seeded_rng();

    let proof = prove(&pk, &arcs, &full_assignment, &mut rng).expect("prove() must succeed");

    let pvk = prepare_verifying_key(&pk.vk);
    let ok = Groth16::<ark_bn254::Bn254>::verify_proof(&pvk, &proof, &[Fr::from(9u64)])
        .expect("Groth16::verify_proof must not error");
    assert!(ok, "valid proof must verify (Ok(true))");
}

#[test]
fn verify_returns_false_for_wrong_public_input() {
    // Build a real proof for x=3 / y=9, then verify with a contradictory
    // public input. The pairing check fails cleanly: verify_proof returns
    // Ok(false), NOT Err. This contract matters for downstream verifiers
    // that distinguish "proof is well-formed but rejects this statement"
    // from "framework-level error".
    let (pk, arcs, full_assignment) = setup_with_witness(3);
    let mut rng = seeded_rng();
    let proof = prove(&pk, &arcs, &full_assignment, &mut rng).expect("prove() must succeed");

    let pvk = prepare_verifying_key(&pk.vk);
    let wrong_public = [Fr::from(100u64)];
    let ok = Groth16::<ark_bn254::Bn254>::verify_proof(&pvk, &proof, &wrong_public)
        .expect("Groth16::verify_proof must not error");
    assert!(!ok, "wrong public input must produce Ok(false), not Err");
}
