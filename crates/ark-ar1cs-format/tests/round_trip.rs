/// Format round-trip, error-rejection, and validation tests.
///
/// Circuit fixture: x * 1 = x
///   Variables: [1(implicit), x(pub), w1(witness), w2(witness)]
///   num_instance_variables=2, num_witness_variables=2, num_constraints=3
use ark_ar1cs_format::{ArcsError, ArcsFile, ArcsHeader, CurveId, VERSION_V0};
use ark_ar1cs_test_fixtures::make_test_matrices;
use ark_bls12_381::Fr as BlsFr;
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintMatrices;

// ---------------------------------------------------------------------------
// Happy-path round-trips
// ---------------------------------------------------------------------------

#[test]
fn round_trip_3constraint_r1cs() {
    let matrices = make_test_matrices();
    let original = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    let mut buf = Vec::new();
    original.write(&mut buf).expect("serialize failed");

    let recovered = ArcsFile::<Fr>::read(&mut buf.as_slice()).expect("deserialize failed");

    assert_eq!(original.header, recovered.header);
    assert_eq!(original.a, recovered.a, "matrix A mismatch");
    assert_eq!(original.b, recovered.b, "matrix B mismatch");
    assert_eq!(original.c, recovered.c, "matrix C mismatch");
}

#[test]
fn round_trip_into_constraint_matrices() {
    let original_matrices = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &original_matrices);

    let mut buf = Vec::new();
    file.write(&mut buf).expect("serialize failed");

    let recovered_file = ArcsFile::<Fr>::read(&mut buf.as_slice()).expect("deserialize failed");
    let recovered_matrices = recovered_file.into_matrices();

    assert_eq!(
        original_matrices.num_instance_variables,
        recovered_matrices.num_instance_variables
    );
    assert_eq!(
        original_matrices.num_witness_variables,
        recovered_matrices.num_witness_variables
    );
    assert_eq!(original_matrices.num_constraints, recovered_matrices.num_constraints);
    assert_eq!(original_matrices.a_num_non_zero, recovered_matrices.a_num_non_zero);
    assert_eq!(original_matrices.a, recovered_matrices.a);
    assert_eq!(original_matrices.b, recovered_matrices.b);
    assert_eq!(original_matrices.c, recovered_matrices.c);
}

/// BLS12-381 round-trip: verifies that the second supported curve's field element
/// encoding/decoding path is exercised (CurveId::Bls12_381).
#[test]
fn round_trip_bls12_381() {
    let a = vec![vec![(BlsFr::from(1u64), 1)]];
    let b = vec![vec![(BlsFr::from(1u64), 0)]];
    let c = vec![vec![(BlsFr::from(1u64), 1)]];
    let matrices = ConstraintMatrices::<BlsFr> {
        num_instance_variables: 2,
        num_witness_variables: 1,
        num_constraints: 1,
        a_num_non_zero: 1,
        b_num_non_zero: 1,
        c_num_non_zero: 1,
        a,
        b,
        c,
    };
    let file = ArcsFile::from_matrices(CurveId::Bls12_381, &matrices);

    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    let recovered = ArcsFile::<BlsFr>::read(&mut buf.as_slice()).unwrap();
    assert_eq!(file.header, recovered.header);
    assert_eq!(file.a, recovered.a);
    assert_eq!(file.b, recovered.b);
    assert_eq!(file.c, recovered.c);
}

// ---------------------------------------------------------------------------
// Header-level error rejection (test ArcsHeader::read directly so the
// checksum layer doesn't shadow these errors)
// ---------------------------------------------------------------------------

#[test]
fn rejects_invalid_magic() {
    // Build a raw 57-byte header with corrupted magic bytes.
    let mut header_bytes = Vec::new();
    ArcsHeader {
        version: VERSION_V0,
        curve_id: CurveId::Bn254,
        num_instance_variables: 2,
        num_witness_variables: 2,
        num_constraints: 3,
        a_non_zero: 3,
        b_non_zero: 3,
        c_non_zero: 3,
    }
    .write(&mut header_bytes)
    .unwrap();
    header_bytes[0] = 0xFF; // corrupt magic

    let err = ArcsHeader::read(&mut header_bytes.as_slice())
        .expect_err("should have rejected invalid magic");
    assert!(matches!(err, ArcsError::InvalidMagic));
}

#[test]
fn rejects_unsupported_curve() {
    let mut header_bytes = Vec::new();
    ArcsHeader {
        version: VERSION_V0,
        curve_id: CurveId::Bn254,
        num_instance_variables: 2,
        num_witness_variables: 2,
        num_constraints: 3,
        a_non_zero: 3,
        b_non_zero: 3,
        c_non_zero: 3,
    }
    .write(&mut header_bytes)
    .unwrap();
    header_bytes[7] = 0xFF; // curve_id byte at offset 7 (6 magic + 1 version)

    let err = ArcsHeader::read(&mut header_bytes.as_slice())
        .expect_err("should have rejected unsupported curve");
    assert!(matches!(err, ArcsError::UnsupportedCurve(0xFF)));
}

#[test]
fn rejects_unsupported_version() {
    let mut header_bytes = Vec::new();
    ArcsHeader {
        version: VERSION_V0,
        curve_id: CurveId::Bn254,
        num_instance_variables: 2,
        num_witness_variables: 2,
        num_constraints: 3,
        a_non_zero: 3,
        b_non_zero: 3,
        c_non_zero: 3,
    }
    .write(&mut header_bytes)
    .unwrap();
    header_bytes[6] = 0x01; // version byte at offset 6 (after 6 magic bytes)

    let err = ArcsHeader::read(&mut header_bytes.as_slice())
        .expect_err("should have rejected unsupported version");
    assert!(matches!(err, ArcsError::UnsupportedVersion(0x01)));
}

// ---------------------------------------------------------------------------
// Checksum tests (test ArcsFile::read end-to-end)
// ---------------------------------------------------------------------------

/// File shorter than the 32-byte checksum trailer → Io(UnexpectedEof).
#[test]
fn rejects_too_short_for_checksum() {
    let buf = vec![0u8; 10]; // 10 < 32
    let err = ArcsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("should reject file shorter than checksum");
    assert!(matches!(err, ArcsError::Io(_)));
}

/// Truncated file (has header but no matrices, > 32 bytes) → ChecksumMismatch.
#[test]
fn rejects_truncated_file() {
    let matrices = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    // Truncate so body is incomplete but file is still > 32 bytes.
    buf.truncate(57); // header only, no matrices, no valid checksum

    let err = ArcsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("should have rejected truncated file");
    assert!(
        matches!(err, ArcsError::ChecksumMismatch),
        "expected ChecksumMismatch, got: {err}"
    );
}

/// Single bit-flip in the body → ChecksumMismatch.
#[test]
fn rejects_checksum_corruption() {
    let matrices = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    // Flip a byte in the body (not the trailing 32-byte checksum).
    let body_len = buf.len() - 32;
    buf[body_len / 2] ^= 0xFF;

    let err = ArcsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("should have rejected corrupted body");
    assert!(matches!(err, ArcsError::ChecksumMismatch));
}

// ---------------------------------------------------------------------------
// validate() tests — construct ArcsFile directly, call validate(), no I/O
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_zero_instance_variables() {
    let matrices = make_test_matrices();
    let mut file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    file.header.num_instance_variables = 0;

    let err = file.validate().expect_err("should reject num_instance_variables=0");
    assert!(matches!(err, ArcsError::ValidationFailed(_)));
}

#[test]
fn validate_rejects_a_non_zero_mismatch() {
    let matrices = make_test_matrices();
    let mut file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    file.header.a_non_zero = 99; // wrong — actual is 3

    let err = file.validate().expect_err("should reject a_non_zero mismatch");
    assert!(matches!(err, ArcsError::ValidationFailed(_)));
}

#[test]
fn validate_rejects_row_count_mismatch() {
    let matrices = make_test_matrices();
    let mut file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    file.header.num_constraints = 5; // wrong — actual row count is 3

    let err = file.validate().expect_err("should reject row count mismatch");
    assert!(matches!(err, ArcsError::ValidationFailed(_)));
}

#[test]
fn validate_rejects_col_out_of_bounds() {
    // num_instance=2, num_witness=2 → max_col=4 (indices 0..3)
    let matrices = make_test_matrices();
    let mut file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    // Inject an out-of-bounds column into matrix a and update the nz count.
    file.a[0].push((Fr::from(1u64), 999));
    file.header.a_non_zero += 1;

    let err = file.validate().expect_err("should reject out-of-bounds column");
    assert!(matches!(err, ArcsError::ValidationFailed(_)));
}
