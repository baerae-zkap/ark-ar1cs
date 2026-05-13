//! R1CS pre-flight (OV-1) integration test.
//!
//! Demonstrates that an invalid assignment is rejected at `prove()`-time
//! with [`ProverError::AssignmentNotSatisfying`] — NOT silently turned into
//! an `Ok(Proof)` that fails verification later. This is the design's
//! single most important footgun guard.
//!
//! Also covers [`ProverError::WitnessLengthMismatch`], the cheap O(1) gate
//! that fires when the caller hands `prove` a slice whose length does not
//! match `arzkey.num_instance_variables + num_witness_variables` — the
//! count-arithmetic guarantee that subsumes the old `bind_check` rule 4.

mod common;

use ark_ar1cs::{prove, ProverError};
use ark_bn254::Fr;
use ark_ff::Field;

use common::{seeded_rng, setup_with_witness};

#[test]
fn invalid_assignment_rejected_before_groth16() {
    // SquareCircuit constraint: x * x = y. Set x = 3, but lie about y by
    // claiming y = 10. Pre-flight is the only thing standing between this
    // assignment and a bogus Ok(Proof).
    let (arzkey, _) = setup_with_witness(3);
    // Wire layout: [ONE, y (instance), x (witness)].
    let lying_assignment: Vec<Fr> = vec![Fr::ONE, Fr::from(10u64), Fr::from(3u64)];

    let mut rng = seeded_rng();
    let err = prove(&arzkey, &lying_assignment, &mut rng).expect_err("prove() must reject");
    assert!(
        matches!(err, ProverError::AssignmentNotSatisfying { row: 0 }),
        "expected AssignmentNotSatisfying {{ row: 0 }}, got {err:?}"
    );
}

/// `prove` rejects a too-short assignment slice with the cheap O(1)
/// `WitnessLengthMismatch` gate — subsumes the old `bind_check` rule 4
/// (count-sum consistency between arzkey and the witness).
#[test]
fn length_mismatch_rejected_before_preflight() {
    let (arzkey, _) = setup_with_witness(3);
    // Layout would be [ONE, y, x]; drop the witness to force a length mismatch.
    let short_assignment: Vec<Fr> = vec![Fr::ONE, Fr::from(9u64)];

    let mut rng = seeded_rng();
    let err = prove(&arzkey, &short_assignment, &mut rng).expect_err("prove() must reject");
    let expected =
        (arzkey.header.num_instance_variables + arzkey.header.num_witness_variables) as usize;
    assert!(
        matches!(
            err,
            ProverError::WitnessLengthMismatch { expected: e, got: 2 } if e == expected
        ),
        "expected WitnessLengthMismatch {{ expected: {expected}, got: 2 }}, got {err:?}"
    );
}
