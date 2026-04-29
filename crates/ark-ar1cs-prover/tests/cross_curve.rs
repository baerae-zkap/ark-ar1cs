//! Phase D Q3 #2 — BLS12-381 cross-curve e2e.
//!
//! BN254 e2e is covered by `tests/e2e.rs`. This file mirrors that flow on
//! BLS12-381 to validate that the prover, the `.arzkey` / `.arwtns`
//! envelopes, and the four `bind_check` rules all stay correct under a
//! different pairing curve. The only thing that varies between BN254 and
//! BLS12-381 in the pipeline is `E: Pairing` and the corresponding scalar
//! field — the envelope bytes, hashes, and prover code are otherwise
//! identical.
//!
//! Per the design doc Q3 ordering: BN254 is stabilized first; this test
//! is added only after the BN254 e2e (Phase C.5) is green so cross-curve
//! coverage is validated by structural similarity, not by parallel
//! development.

#![cfg(not(target_arch = "wasm32"))]

mod common;

use ark_ar1cs_prover::{prove, verify};
use common::{seeded_rng, setup_with_witness_bls};

#[test]
fn bls12_381_setup_prove_verify_e2e() {
    let x_value = 17u64;
    let (arzkey, arwtns) = setup_with_witness_bls(x_value);

    // arwtns.instance = [y = x*x] — the only public input the verifier
    // sees (the implicit "1" wire is reconstructed inside prove()).
    let public_inputs = arwtns.instance.clone();

    let mut rng = seeded_rng();
    let proof = prove(&arzkey, &arwtns, &mut rng).expect("prove on BLS12-381 should succeed");

    let ok = verify(&arzkey, &public_inputs, &proof)
        .expect("verify on BLS12-381 should not error");
    assert!(
        ok,
        "BLS12-381 e2e: a valid witness must produce a verifying proof"
    );
}
