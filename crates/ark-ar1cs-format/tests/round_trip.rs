/// Priority 1 test: schema round-trip with no file I/O.
///
/// Constructs a hardcoded 3-constraint R1CS, serializes to Vec<u8>,
/// deserializes back, and asserts byte-for-byte matrix equality.
///
/// Circuit: x * 1 = x (trivial, just enough to have real matrix entries)
///   Variables: [1, x, w1, w2]  (num_instance_variables=2, num_witness_variables=2)
///   Constraints (3):
///     A[0] * B[0] = C[0]  →  x * 1 = x
///     A[1] * B[1] = C[1]  →  w1 * 1 = w1
///     A[2] * B[2] = C[2]  →  w2 * x = w1
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintMatrices;

fn make_test_matrices() -> ConstraintMatrices<Fr> {
    // Variable indices:
    //   0 = implicit "1" wire
    //   1 = x  (public input)
    //   2 = w1 (witness)
    //   3 = w2 (witness)
    let a = vec![
        vec![(Fr::from(1u64), 1)],              // row 0: 1*x
        vec![(Fr::from(1u64), 2)],              // row 1: 1*w1
        vec![(Fr::from(1u64), 3)],              // row 2: 1*w2
    ];
    let b = vec![
        vec![(Fr::from(1u64), 0)],              // row 0: 1*"1"
        vec![(Fr::from(1u64), 0)],              // row 1: 1*"1"
        vec![(Fr::from(1u64), 1)],              // row 2: 1*x
    ];
    let c = vec![
        vec![(Fr::from(1u64), 1)],              // row 0: 1*x
        vec![(Fr::from(1u64), 2)],              // row 1: 1*w1
        vec![(Fr::from(1u64), 2)],              // row 2: 1*w1
    ];

    ConstraintMatrices {
        num_instance_variables: 2, // includes implicit "1" wire
        num_witness_variables: 2,
        num_constraints: 3,
        a_num_non_zero: 3,
        b_num_non_zero: 3,
        c_num_non_zero: 3,
        a,
        b,
        c,
    }
}

#[test]
fn round_trip_3constraint_r1cs() {
    let matrices = make_test_matrices();
    let original = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    // Serialize to bytes
    let mut buf = Vec::new();
    original.write(&mut buf).expect("serialize failed");

    // Deserialize back (includes validate())
    let recovered = ArcsFile::<Fr>::read(&mut buf.as_slice()).expect("deserialize failed");

    // Header fields must match
    assert_eq!(original.header, recovered.header);

    // Matrix entries must match byte-for-byte (PartialEq on Fr and usize)
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

    assert_eq!(original_matrices.num_instance_variables, recovered_matrices.num_instance_variables);
    assert_eq!(original_matrices.num_witness_variables, recovered_matrices.num_witness_variables);
    assert_eq!(original_matrices.num_constraints, recovered_matrices.num_constraints);
    assert_eq!(original_matrices.a_num_non_zero, recovered_matrices.a_num_non_zero);
    assert_eq!(original_matrices.a, recovered_matrices.a);
    assert_eq!(original_matrices.b, recovered_matrices.b);
    assert_eq!(original_matrices.c, recovered_matrices.c);
}

#[test]
fn rejects_invalid_magic() {
    let matrices = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    let mut buf = Vec::new();
    file.write(&mut buf).expect("serialize failed");

    // Corrupt magic bytes
    buf[0] = 0xFF;

    let err = ArcsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("should have rejected invalid magic");
    assert!(matches!(err, ark_ar1cs_format::ArcsError::InvalidMagic));
}

#[test]
fn rejects_unsupported_curve() {
    let matrices = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    let mut buf = Vec::new();
    file.write(&mut buf).expect("serialize failed");

    // Corrupt curve_id byte (index 7: 6 magic + 1 version = offset 7)
    buf[7] = 0xFF;

    let err = ArcsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("should have rejected unsupported curve");
    assert!(matches!(err, ark_ar1cs_format::ArcsError::UnsupportedCurve(0xFF)));
}

#[test]
fn rejects_truncated_file() {
    let matrices = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    let mut buf = Vec::new();
    file.write(&mut buf).expect("serialize failed");

    // Truncate to just the header (57 bytes: 6 magic + 3 meta + 6*8 counts)
    buf.truncate(57);

    let err = ArcsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("should have rejected truncated file");
    // Should produce an Io or Serialization error (unexpected EOF)
    assert!(
        matches!(err, ark_ar1cs_format::ArcsError::Io(_) | ark_ar1cs_format::ArcsError::Serialization(_)),
        "unexpected error type: {err}"
    );
}
