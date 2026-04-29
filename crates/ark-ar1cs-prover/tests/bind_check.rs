//! `bind_check` integration tests.
//!
//! Five tests total: one happy path plus one negative per
//! [`ArtifactMismatchReason`] variant (TEST-2). Each negative test mutates
//! exactly one header field on a freshly-built artifact pair so that the
//! rule under test fires and earlier-running rules still pass.
//!
//! Rule execution order (cheap→expensive, see `bind.rs`):
//!   rule 1 — curve_id           (O(1))
//!   rule 2 — ar1cs_blake3       (O(1))
//!   rule 4 — count consistency  (O(1))
//!   rule 3 — self-consistency   (O(ar1cs_byte_len))

mod common;

use ark_ar1cs_format::CurveId;
use ark_ar1cs_prover::{bind_check, ArtifactMismatchReason, ProverError};

use common::setup_with_witness;

#[test]
fn happy_path_matching_artifacts() {
    let (arzkey, arwtns) = setup_with_witness(7);
    bind_check(&arzkey, &arwtns).expect("bind_check should accept matching artifacts");
}

/// Rule 1 — header `curve_id` mismatch surfaces `ArtifactMismatchReason::CurveId`.
#[test]
fn curve_id_mismatch_returns_curve_id_variant() {
    let (arzkey, mut arwtns) = setup_with_witness(3);
    // arzkey is BN254; force a curve disagreement by relabelling the witness.
    arwtns.header.curve_id = CurveId::Bls12_381;

    let err = bind_check(&arzkey, &arwtns).expect_err("bind_check must reject");
    assert!(
        matches!(
            err,
            ProverError::ArtifactMismatch {
                reason: ArtifactMismatchReason::CurveId { .. }
            }
        ),
        "expected ArtifactMismatch::CurveId, got {err:?}"
    );

    // Also pin down the structured payload so a regression that drops the
    // arzkey/arwtns identifiers from the variant is caught.
    if let ProverError::ArtifactMismatch {
        reason: ArtifactMismatchReason::CurveId { arzkey: a, arwtns: w },
    } = err
    {
        assert_eq!(a, CurveId::Bn254 as u8);
        assert_eq!(w, CurveId::Bls12_381 as u8);
    } else {
        unreachable!()
    }
}

/// Rule 2 — `ar1cs_blake3` mismatch (different circuit identity) surfaces
/// `ArtifactMismatchReason::Ar1csBlake3`. Curve_id (rule 1) still matches.
#[test]
fn ar1cs_blake3_mismatch_returns_ar1cs_blake3_variant() {
    let (arzkey, mut arwtns) = setup_with_witness(3);
    arwtns.header.ar1cs_blake3[0] ^= 0x01;

    let err = bind_check(&arzkey, &arwtns).expect_err("bind_check must reject");
    assert!(
        matches!(
            err,
            ProverError::ArtifactMismatch {
                reason: ArtifactMismatchReason::Ar1csBlake3
            }
        ),
        "expected ArtifactMismatch::Ar1csBlake3, got {err:?}"
    );
}

/// Rule 4 — count sum mismatch surfaces `ArtifactMismatchReason::CountMismatch`.
/// Both blake3 hashes still match (rule 2 passes), so the failure is exactly
/// the count-arithmetic violation.
#[test]
fn count_mismatch_returns_count_mismatch_variant() {
    let (arzkey, mut arwtns) = setup_with_witness(3);
    let original = arwtns.header.num_witness;
    arwtns.header.num_witness = original.saturating_add(7);

    let err = bind_check(&arzkey, &arwtns).expect_err("bind_check must reject");
    assert!(
        matches!(
            err,
            ProverError::ArtifactMismatch {
                reason: ArtifactMismatchReason::CountMismatch { .. }
            }
        ),
        "expected ArtifactMismatch::CountMismatch, got {err:?}"
    );

    if let ProverError::ArtifactMismatch {
        reason: ArtifactMismatchReason::CountMismatch { expected, got },
    } = err
    {
        // arzkey: 2 instance + 1 witness ⇒ expected = (2-1) + 1 = 2.
        // arwtns: num_instance=1, num_witness=1+7=8 ⇒ got = 9.
        assert_eq!(expected, 2);
        assert_eq!(got, 1 + (original + 7));
    } else {
        unreachable!()
    }
}

/// Rule 3 — `.arzkey` self-consistency: `arzkey.arcs().body_blake3()` does
/// not equal `arzkey.header.ar1cs_blake3`. To isolate this rule we mutate
/// BOTH headers' `ar1cs_blake3` to the same wrong value so rules 1, 2, 4 all
/// pass and only rule 3 fires.
#[test]
fn self_consistency_mismatch_returns_self_consistency_variant() {
    let (mut arzkey, mut arwtns) = setup_with_witness(3);
    arzkey.header.ar1cs_blake3[0] ^= 0x01;
    arwtns.header.ar1cs_blake3[0] ^= 0x01;

    let err = bind_check(&arzkey, &arwtns).expect_err("bind_check must reject");
    assert!(
        matches!(
            err,
            ProverError::ArtifactMismatch {
                reason: ArtifactMismatchReason::SelfConsistency
            }
        ),
        "expected ArtifactMismatch::SelfConsistency, got {err:?}"
    );
}
