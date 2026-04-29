/// `.arwtns` happy-path round-trip and basic-API tests.
use ark_ar1cs_format::CurveId;
use ark_ar1cs_wtns::{ArwtnsFile, ArwtnsHeader, ARWTNS_VERSION_V0};
use ark_bn254::Fr;
use ark_ff::Field;

#[test]
fn round_trip_bn254() {
    let blake3 = [42u8; 32];
    let instance = vec![Fr::from(1u64), Fr::from(7u64)];
    let witness = vec![Fr::from(13u64), Fr::from(17u64), Fr::from(19u64)];

    let original = ArwtnsFile::from_assignments(CurveId::Bn254, blake3, &instance, &witness);

    let mut buf = Vec::new();
    original.write(&mut buf).expect("write failed");

    let recovered = ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect("read failed");

    assert_eq!(original.header, recovered.header);
    assert_eq!(original.instance, recovered.instance);
    assert_eq!(original.witness, recovered.witness);
}

#[test]
fn from_assignments_populates_header() {
    let blake3 = [9u8; 32];
    let instance = vec![Fr::from(2u64)];
    let witness = vec![Fr::from(3u64), Fr::from(5u64)];

    let f = ArwtnsFile::from_assignments(CurveId::Bn254, blake3, &instance, &witness);
    assert_eq!(
        f.header,
        ArwtnsHeader {
            version: ARWTNS_VERSION_V0,
            curve_id: CurveId::Bn254,
            ar1cs_blake3: blake3,
            num_instance: 1,
            num_witness: 2,
        }
    );
}

#[test]
fn full_assignment_with_one_wire_prepends_one() {
    let blake3 = [0u8; 32];
    let instance = vec![Fr::from(2u64), Fr::from(3u64)];
    let witness = vec![Fr::from(5u64)];

    let f = ArwtnsFile::from_assignments(CurveId::Bn254, blake3, &instance, &witness);
    let full = f.full_assignment_with_one_wire();

    assert_eq!(full.len(), 4);
    assert_eq!(full[0], Fr::ONE);
    assert_eq!(full[1], Fr::from(2u64));
    assert_eq!(full[2], Fr::from(3u64));
    assert_eq!(full[3], Fr::from(5u64));
}

#[test]
fn empty_assignments_round_trip() {
    let blake3 = [1u8; 32];
    let f = ArwtnsFile::<Fr>::from_assignments(CurveId::Bn254, blake3, &[], &[]);

    let mut buf = Vec::new();
    f.write(&mut buf).unwrap();
    let recovered = ArwtnsFile::<Fr>::read(&mut buf.as_slice()).unwrap();

    assert_eq!(recovered.header.num_instance, 0);
    assert_eq!(recovered.header.num_witness, 0);
    assert!(recovered.instance.is_empty());
    assert!(recovered.witness.is_empty());

    let full = recovered.full_assignment_with_one_wire();
    assert_eq!(full, vec![Fr::ONE]);
}

#[test]
fn validate_passes_for_constructed_file() {
    let blake3 = [0u8; 32];
    let f = ArwtnsFile::<Fr>::from_assignments(
        CurveId::Bn254,
        blake3,
        &[Fr::from(1u64)],
        &[Fr::from(2u64)],
    );
    f.validate().expect("validate should pass on freshly constructed file");
}
