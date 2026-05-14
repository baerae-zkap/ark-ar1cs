//! CORE-AC-A13 — predicted-size guard.
//!
//! Verifies that `ArcsFile::read` rejects forged headers whose declared
//! counts imply more than `MAX_FILE_BYTES` of matrix payload, *before*
//! `read_matrix` issues a `Vec::with_capacity(num_rows)` that could
//! request a `u64::MAX`-sized allocation.
//!
//! Hard guard: every forged buffer must stay well under 4 KiB so no
//! `MAX_FILE_BYTES + 1`-sized allocation can happen in this test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ark_ar1cs::format::header::{CurveId, MAGIC, VERSION_V0};
use ark_ar1cs::format::{ArcsError, ArcsFile, MAX_FILE_BYTES};
use ark_bn254::Fr;

/// Build a 57-byte `ArcsHeader` body with the given declared counts and
/// append a valid Blake3 trailer over those bytes. Returned buffer is
/// `57 + 32 = 89` bytes regardless of the declared count magnitudes —
/// only the *declared* fields are inflated.
fn forge_header_with_counts(
    num_instance_variables: u64,
    num_witness_variables: u64,
    num_constraints: u64,
    a_non_zero: u64,
    b_non_zero: u64,
    c_non_zero: u64,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(57);
    body.extend_from_slice(MAGIC);
    body.push(VERSION_V0);
    body.push(CurveId::Bn254 as u8);
    body.push(0x00); // reserved
    body.extend_from_slice(&num_instance_variables.to_le_bytes());
    body.extend_from_slice(&num_witness_variables.to_le_bytes());
    body.extend_from_slice(&num_constraints.to_le_bytes());
    body.extend_from_slice(&a_non_zero.to_le_bytes());
    body.extend_from_slice(&b_non_zero.to_le_bytes());
    body.extend_from_slice(&c_non_zero.to_le_bytes());
    assert_eq!(body.len(), 57, "header body must be exactly 57 bytes");

    let trailer = blake3::hash(&body);
    body.extend_from_slice(trailer.as_bytes());
    body
}

#[test]
fn forged_huge_num_constraints_rejected_as_file_too_large() {
    // Pick `num_constraints` so the lower-bound row-count overhead alone
    // (`8 * num_constraints` per matrix × 3 matrices = `24 * n`) exceeds
    // MAX_FILE_BYTES, before any non-zero contribution.
    let huge_n = MAX_FILE_BYTES / 8 + 1;
    let buf = forge_header_with_counts(1, 0, huge_n, 0, 0, 0);

    assert!(
        buf.len() < 4096,
        "A13 test buffer must stay under 4 KiB (got {} bytes)",
        buf.len()
    );

    let err = ArcsFile::<Fr>::read(&mut &buf[..])
        .expect_err("forged huge num_constraints must be rejected");
    assert!(
        matches!(err, ArcsError::FileTooLarge),
        "expected ArcsError::FileTooLarge, got {err:?}"
    );
}

#[test]
fn forged_huge_a_non_zero_rejected_as_file_too_large() {
    // Pick `a_non_zero` so the per-non-zero lower bound alone
    // (`9 * a_non_zero`) exceeds MAX_FILE_BYTES, with `num_constraints`
    // small (so this exercises the non-zero contribution, not the
    // row-count one).
    let huge_nz = MAX_FILE_BYTES / 9 + 1;
    let buf = forge_header_with_counts(1, 0, 1, huge_nz, 0, 0);

    assert!(
        buf.len() < 4096,
        "A13 test buffer must stay under 4 KiB (got {} bytes)",
        buf.len()
    );

    let err =
        ArcsFile::<Fr>::read(&mut &buf[..]).expect_err("forged huge a_non_zero must be rejected");
    assert!(
        matches!(err, ArcsError::FileTooLarge),
        "expected ArcsError::FileTooLarge, got {err:?}"
    );
}

#[test]
fn forged_u64_max_counts_overflow_rejected_as_file_too_large() {
    // Counts saturated at `u64::MAX` make the predicted lower bound
    // overflow on `checked_mul`; the guard treats that as FileTooLarge
    // rather than silently saturating.
    let buf = forge_header_with_counts(1, 0, u64::MAX, u64::MAX, u64::MAX, u64::MAX);

    assert!(
        buf.len() < 4096,
        "A13 test buffer must stay under 4 KiB (got {} bytes)",
        buf.len()
    );

    let err =
        ArcsFile::<Fr>::read(&mut &buf[..]).expect_err("u64::MAX header counts must be rejected");
    assert!(
        matches!(err, ArcsError::FileTooLarge),
        "expected ArcsError::FileTooLarge, got {err:?}"
    );
}
