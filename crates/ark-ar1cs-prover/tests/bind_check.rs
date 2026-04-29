//! `bind_check` integration tests.
//!
//! Commit 1 covers the happy path: an artifact pair produced by a real
//! Groth16 setup passes the bind rules. Commits 2+ extend with one negative
//! test per distinct `ArtifactMismatchReason` variant (TEST-2).

mod common;

use ark_ar1cs_prover::bind_check;

use common::setup_with_witness;

#[test]
fn happy_path_matching_artifacts() {
    let (arzkey, arwtns) = setup_with_witness(7);
    bind_check(&arzkey, &arwtns).expect("bind_check should accept matching artifacts");
}
