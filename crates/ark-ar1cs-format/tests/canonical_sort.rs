/// Canonical-sort tests (Phase A.1, ARCH-1).
///
/// `write_matrix` sorts `(coeff, var_idx)` pairs by `var_idx` ascending within
/// each row, so two semantically-equal `ConstraintMatrices` with reordered row
/// entries serialize to byte-identical `.ar1cs` files and yield identical
/// `body_blake3()` values. `body_blake3()` itself returns the same 32 bytes
/// the writer appends as trailer.
use ark_ar1cs_format::test_fixtures::make_test_matrices;
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintMatrices;

fn matrices_with_row_a(row: Vec<(Fr, usize)>) -> ConstraintMatrices<Fr> {
    ConstraintMatrices {
        num_instance_variables: 2,
        num_witness_variables: 2,
        num_constraints: 1,
        a_num_non_zero: row.len(),
        b_num_non_zero: 1,
        c_num_non_zero: 1,
        a: vec![row],
        b: vec![vec![(Fr::from(1u64), 0)]],
        c: vec![vec![(Fr::from(1u64), 1)]],
    }
}

#[test]
fn canonical_sort_within_row_byte_identical() {
    // Same content, different (coeff, var_idx) ordering within row 0 of matrix A.
    let asc = vec![
        (Fr::from(11u64), 0),
        (Fr::from(22u64), 1),
        (Fr::from(33u64), 3),
    ];
    let scrambled = vec![
        (Fr::from(33u64), 3),
        (Fr::from(11u64), 0),
        (Fr::from(22u64), 1),
    ];

    let f_asc = ArcsFile::from_matrices(CurveId::Bn254, &matrices_with_row_a(asc));
    let f_scrambled =
        ArcsFile::from_matrices(CurveId::Bn254, &matrices_with_row_a(scrambled));

    let mut b_asc = Vec::new();
    f_asc.write(&mut b_asc).unwrap();
    let mut b_scrambled = Vec::new();
    f_scrambled.write(&mut b_scrambled).unwrap();

    assert_eq!(
        b_asc, b_scrambled,
        "scrambled row must produce byte-identical .ar1cs output"
    );
    assert_eq!(
        f_asc.body_blake3(),
        f_scrambled.body_blake3(),
        "scrambled row must produce identical body_blake3()"
    );
}

#[test]
fn body_blake3_matches_trailer() {
    let file = ArcsFile::from_matrices(CurveId::Bn254, &make_test_matrices());
    let mut buf = Vec::new();
    file.write(&mut buf).unwrap();

    let trailer: [u8; 32] = buf[buf.len() - 32..]
        .try_into()
        .expect("file must be at least 32 bytes after write");
    assert_eq!(file.body_blake3(), trailer);
}
