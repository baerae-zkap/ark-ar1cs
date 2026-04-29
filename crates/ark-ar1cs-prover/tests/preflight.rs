//! R1CS pre-flight (OV-1) integration test.
//!
//! Demonstrates that an invalid assignment is rejected at `prove()`-time
//! with [`ProverError::AssignmentNotSatisfying`] — NOT silently turned into
//! an `Ok(Proof)` that fails verification later. This is the design's
//! single most important footgun guard.

mod common;

use ark_ar1cs_format::CurveId;
use ark_ar1cs_prover::{prove, ProverError};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_bn254::Fr;

use common::{seeded_rng, setup_with_witness};

#[test]
fn invalid_assignment_rejected_before_groth16() {
    // SquareCircuit constraint: x * x = y.  Set x = 3, but lie about y by
    // claiming y = 10. ArcsFile binds the same circuit, so bind_check passes;
    // pre-flight is the only thing standing between this assignment and a
    // bogus Ok(Proof).
    let (arzkey, _) = setup_with_witness(3);
    let lying = ArwtnsFile::<Fr>::from_assignments(
        CurveId::Bn254,
        arzkey.header.ar1cs_blake3,
        &[Fr::from(10u64)],
        &[Fr::from(3u64)],
    );

    let mut rng = seeded_rng();
    let err = prove(&arzkey, &lying, &mut rng).expect_err("prove() must reject");
    assert!(
        matches!(err, ProverError::AssignmentNotSatisfying { row: 0 }),
        "expected AssignmentNotSatisfying {{ row: 0 }}, got {err:?}"
    );
}
