#![allow(clippy::unwrap_used, clippy::expect_used)]

//! BLS12-381 cross-curve e2e for the post-migration prove path.
//!
//! BN254 e2e is covered by `tests/prove_e2e.rs`. This file mirrors that
//! flow on BLS12-381 to validate that the prover stays correct under a
//! different pairing curve. The only thing that varies between BN254
//! and BLS12-381 is `E: Pairing` and the corresponding scalar field —
//! the codec bytes, hashes, and prover code are otherwise identical.
//!
//! Curve mismatch (the historical `bind_check` rule 1) is now enforced
//! at the *type* level by the `prove` signature — `&ProvingKey<E>` +
//! `&ArcsFile<E::ScalarField>` share `E`, so a wrong-curve pair fails
//! to compile rather than failing at runtime. The previous
//! `wrong_curve_arzkey_rejected_at_parse_time` integration test
//! exercised the `.arzkey` envelope's runtime curve guard, which is
//! gone with the envelope; the invariant it pinned now lives in the
//! Rust type system.

#![cfg(not(target_arch = "wasm32"))]

mod common;

use ark_ar1cs::prove;
use ark_bls12_381::Bls12_381;
use ark_groth16::{prepare_verifying_key, Groth16};

use common::{seeded_rng, setup_with_witness_bls};

#[test]
fn bls12_381_setup_prove_verify_e2e() {
    let x_value = 17u64;
    let (pk, arcs, full_assignment) = setup_with_witness_bls(x_value);

    // SquareCircuit wire layout puts y at index 1 (the only public input
    // the verifier sees; the implicit "1" wire is at index 0 and consumed
    // by Groth16 internally).
    let public_inputs = vec![full_assignment[1]];

    let mut rng = seeded_rng();
    let proof =
        prove(&pk, &arcs, &full_assignment, &mut rng).expect("prove on BLS12-381 should succeed");

    let pvk = prepare_verifying_key(&pk.vk);
    let ok = Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &public_inputs)
        .expect("Groth16::verify_proof on BLS12-381 should not error");
    assert!(
        ok,
        "BLS12-381 e2e: a valid witness must produce a verifying proof"
    );
}
