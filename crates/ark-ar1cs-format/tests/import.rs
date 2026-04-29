/// Importer tests: replay, curve-ID guard, and edge cases.
use ark_ar1cs_format::importer::ImportedCircuit;
use ark_ar1cs_format::test_fixtures::make_test_matrices;
use ark_ar1cs_format::{ArcsError, ArcsFile, CurveId};
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, ConstraintSynthesizer};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serialize_fixture() -> Vec<u8> {
    let file = ArcsFile::from_matrices(CurveId::Bn254, &make_test_matrices());
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();
    buf
}

// ---------------------------------------------------------------------------
// Happy-path: matrix replay
// ---------------------------------------------------------------------------

/// Serialise the test matrices, import them, replay into a fresh CS,
/// finalise, extract matrices, and compare with originals.
#[test]
fn imported_circuit_produces_same_matrices() {
    let original = make_test_matrices();

    let file = ArcsFile::from_matrices(CurveId::Bn254, &original);
    let mut buf = Vec::new();
    file.write(&mut buf).expect("serialize failed");

    let circuit =
        ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice(), CurveId::Bn254)
            .expect("import failed");

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints failed");
    cs.finalize();

    let recovered = cs.to_matrices().expect("to_matrices failed");

    assert_eq!(original.num_instance_variables, recovered.num_instance_variables);
    assert_eq!(original.num_witness_variables, recovered.num_witness_variables);
    assert_eq!(original.num_constraints, recovered.num_constraints);
    assert_eq!(original.a_num_non_zero, recovered.a_num_non_zero);
    assert_eq!(original.b_num_non_zero, recovered.b_num_non_zero);
    assert_eq!(original.c_num_non_zero, recovered.c_num_non_zero);
    assert_eq!(original.a, recovered.a, "matrix A");
    assert_eq!(original.b, recovered.b, "matrix B");
    assert_eq!(original.c, recovered.c, "matrix C");
}

/// `ImportedCircuit` must be Clone so callers can consume it twice.
#[test]
fn imported_circuit_is_clone() {
    let buf = serialize_fixture();

    let circuit = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice(), CurveId::Bn254).unwrap();
    let circuit2 = circuit.clone();

    for c in [circuit, circuit2] {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let m = cs.to_matrices().unwrap();
        assert_eq!(m.num_constraints, 3);
    }
}

// ---------------------------------------------------------------------------
// Curve-ID guard
// ---------------------------------------------------------------------------

/// Importing a BN254 file while claiming BLS12-381 must return CurveIdMismatch.
#[test]
fn rejects_curve_id_mismatch() {
    let buf = serialize_fixture(); // BN254 file

    let result = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice(), CurveId::Bls12_381);
    assert!(result.is_err(), "should have rejected curve-ID mismatch");
    let err = result.unwrap_err();

    assert!(
        matches!(
            err,
            ArcsError::CurveIdMismatch {
                expected: CurveId::Bls12_381,
                found: CurveId::Bn254,
            }
        ),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Edge cases: degenerate variable counts
// ---------------------------------------------------------------------------

/// num_instance_variables = 1 — only the implicit "1" wire, no explicit public inputs.
/// The importer should allocate 0 explicit public inputs (1 − 1 = 0) and succeed.
#[test]
fn num_instance_one_no_explicit_inputs() {
    // One constraint: 1 * w0 = w0
    let a = vec![vec![(Fr::from(1u64), 0)]]; // 1*"1"
    let b = vec![vec![(Fr::from(1u64), 1)]]; // 1*w0
    let c = vec![vec![(Fr::from(1u64), 1)]]; // 1*w0

    let matrices = ConstraintMatrices {
        num_instance_variables: 1, // only the "1" wire — no explicit public inputs
        num_witness_variables: 1,
        num_constraints: 1,
        a_num_non_zero: 1,
        b_num_non_zero: 1,
        c_num_non_zero: 1,
        a,
        b,
        c,
    };

    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    let circuit = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice(), CurveId::Bn254)
        .expect("import failed");
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("generate_constraints failed");
    cs.finalize();

    let recovered = cs.to_matrices().expect("to_matrices failed");
    assert_eq!(recovered.num_instance_variables, 1);
    assert_eq!(recovered.num_witness_variables, 1);
    assert_eq!(recovered.num_constraints, 1);
}

/// num_witness_variables = 0 — circuit with only public inputs, no witnesses.
/// The importer should allocate 0 witnesses and succeed.
#[test]
fn num_witness_zero() {
    // One constraint: x * 1 = x  (no witnesses)
    let a = vec![vec![(Fr::from(1u64), 1)]]; // 1*x
    let b = vec![vec![(Fr::from(1u64), 0)]]; // 1*"1"
    let c = vec![vec![(Fr::from(1u64), 1)]]; // 1*x

    let matrices = ConstraintMatrices {
        num_instance_variables: 2, // "1" wire + x
        num_witness_variables: 0,
        num_constraints: 1,
        a_num_non_zero: 1,
        b_num_non_zero: 1,
        c_num_non_zero: 1,
        a,
        b,
        c,
    };

    let file = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    let circuit = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice(), CurveId::Bn254)
        .expect("import failed");
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("generate_constraints failed");
    cs.finalize();

    let recovered = cs.to_matrices().expect("to_matrices failed");
    assert_eq!(recovered.num_instance_variables, 2);
    assert_eq!(recovered.num_witness_variables, 0);
    assert_eq!(recovered.num_constraints, 1);
}
