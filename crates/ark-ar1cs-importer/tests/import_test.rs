/// Priority 2 test: full circuit round-trip through the importer.
///
/// Verifies that `ImportedCircuit::generate_constraints` replays the stored
/// matrices exactly — producing the same `ConstraintMatrices` as the original.
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_importer::ImportedCircuit;
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, ConstraintSynthesizer};

/// Same 3-constraint test circuit used in core-format round_trip tests.
fn make_test_matrices() -> ConstraintMatrices<Fr> {
    // Variables: [1(implicit), x(pub), w1(witness), w2(witness)]
    // num_instance_variables = 2 (includes the "1" wire)
    // num_witness_variables  = 2
    let a = vec![
        vec![(Fr::from(1u64), 1)],
        vec![(Fr::from(1u64), 2)],
        vec![(Fr::from(1u64), 3)],
    ];
    let b = vec![
        vec![(Fr::from(1u64), 0)],
        vec![(Fr::from(1u64), 0)],
        vec![(Fr::from(1u64), 1)],
    ];
    let c = vec![
        vec![(Fr::from(1u64), 1)],
        vec![(Fr::from(1u64), 2)],
        vec![(Fr::from(1u64), 2)],
    ];
    ConstraintMatrices {
        num_instance_variables: 2,
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

/// Serialize the test matrices, import them, replay into a fresh CS,
/// finalize, extract matrices, and compare with originals.
#[test]
fn imported_circuit_produces_same_matrices() {
    let original = make_test_matrices();

    // --- export ---
    let file = ArcsFile::from_matrices(CurveId::Bn254, &original);
    let mut buf = Vec::new();
    file.write(&mut buf).expect("serialize failed");

    // --- import ---
    let circuit =
        ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice()).expect("import failed");

    // --- replay into fresh constraint system ---
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints failed");
    cs.finalize();

    let recovered = cs.to_matrices().expect("to_matrices failed");

    // --- compare ---
    assert_eq!(
        original.num_instance_variables, recovered.num_instance_variables,
        "num_instance_variables"
    );
    assert_eq!(
        original.num_witness_variables, recovered.num_witness_variables,
        "num_witness_variables"
    );
    assert_eq!(original.num_constraints, recovered.num_constraints, "num_constraints");
    assert_eq!(original.a_num_non_zero, recovered.a_num_non_zero, "a_num_non_zero");
    assert_eq!(original.b_num_non_zero, recovered.b_num_non_zero, "b_num_non_zero");
    assert_eq!(original.c_num_non_zero, recovered.c_num_non_zero, "c_num_non_zero");
    assert_eq!(original.a, recovered.a, "matrix A");
    assert_eq!(original.b, recovered.b, "matrix B");
    assert_eq!(original.c, recovered.c, "matrix C");
}

/// `ImportedCircuit` must be Clone so tests (and callers) can consume it twice.
#[test]
fn imported_circuit_is_clone() {
    let original = make_test_matrices();
    let file = ArcsFile::from_matrices(CurveId::Bn254, &original);
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    let circuit = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice()).unwrap();
    let circuit2 = circuit.clone();

    // Both clones replay identically.
    for c in [circuit, circuit2] {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let m = cs.to_matrices().unwrap();
        assert_eq!(m.num_constraints, 3);
    }
}
