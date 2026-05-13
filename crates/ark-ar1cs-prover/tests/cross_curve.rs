//! Phase D Q3 #2 — BLS12-381 cross-curve e2e.
//!
//! BN254 e2e is covered by `tests/e2e.rs`. This file mirrors that flow on
//! BLS12-381 to validate that the prover and the `.arzkey` envelope stay
//! correct under a different pairing curve. The only thing that varies
//! between BN254 and BLS12-381 in the pipeline is `E: Pairing` and the
//! corresponding scalar field — the envelope bytes, hashes, and prover
//! code are otherwise identical.
//!
//! The second test pins down the old `bind_check` rule 1 (curve_id):
//! deserializing an `ArzkeyFile<E>` whose header `curve_id` disagrees with
//! type-level `E` is rejected at parse time by `ArzkeyFile::read`, so the
//! prover never sees a wrong-curve artifact in the first place.
//!
//! Per the design doc Q3 ordering: BN254 is stabilized first; this test
//! is added only after the BN254 e2e (Phase C.5) is green so cross-curve
//! coverage is validated by structural similarity, not by parallel
//! development.

#![cfg(not(target_arch = "wasm32"))]

mod common;

use ark_ar1cs_prover::{prove, verify};
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bls12_381::Bls12_381;
use ark_bn254::{Bn254, Fr as BnFr};

use common::{seeded_rng, setup_with_witness, setup_with_witness_bls};

#[test]
fn bls12_381_setup_prove_verify_e2e() {
    let x_value = 17u64;
    let (arzkey, full_assignment) = setup_with_witness_bls(x_value);

    // SquareCircuit wire layout puts y at index 1 (the only public input
    // the verifier sees; the implicit "1" wire is at index 0 and consumed
    // by Groth16 internally).
    let public_inputs = vec![full_assignment[1]];

    let mut rng = seeded_rng();
    let proof =
        prove(&arzkey, &full_assignment, &mut rng).expect("prove on BLS12-381 should succeed");

    let ok = verify(&arzkey, &public_inputs, &proof).expect("verify on BLS12-381 should not error");
    assert!(
        ok,
        "BLS12-381 e2e: a valid witness must produce a verifying proof"
    );
}

/// Old `bind_check` rule 1 — curve_id mismatch — is now enforced at the
/// parse boundary by `ArzkeyFile::<E>::read`. Writing a BN254 arzkey and
/// then trying to read it back as `ArzkeyFile::<Bls12_381>` must fail; the
/// prover never sees a wrong-curve artifact.
#[test]
fn wrong_curve_arzkey_rejected_at_parse_time() {
    let (arzkey_bn254, _) = setup_with_witness(3);

    let mut bytes = Vec::new();
    arzkey_bn254
        .write(&mut bytes)
        .expect("BN254 arzkey should serialize");

    // Re-parse the same bytes under the wrong pairing curve.
    let res = ArzkeyFile::<Bls12_381>::read(&mut bytes.as_slice());
    assert!(
        res.is_err(),
        "ArzkeyFile::<Bls12_381>::read must reject BN254 bytes (rule 1)"
    );

    // Sanity: parsing under the correct curve still works.
    let ok = ArzkeyFile::<Bn254>::read(&mut bytes.as_slice());
    assert!(
        ok.is_ok(),
        "ArzkeyFile::<Bn254>::read must accept its own bytes"
    );
    // Silence the unused `BnFr` import on platforms that strip dead code
    // imports out of the binary.
    let _ = BnFr::from(1u64);
}
