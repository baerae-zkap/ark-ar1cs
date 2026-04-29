/// `.arzkey` negative tests — every malformed scenario asserts a distinct
/// structured `ArzkeyError` variant via exact-match (CQ-4). Includes
/// pre-allocation OOM guards (TEST-3) and the VK duplication consistency
/// check (OV-2 → VkDuplicationDrift).
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_zkey::{ArzkeyError, ArzkeyFile, MAX_ARZKEY_BYTES};
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_serialize::CanonicalSerialize;
use rand::{rngs::StdRng, SeedableRng};

// ---------------------------------------------------------------------------
// Header field offsets (mirror of crate::header layout, for byte-level edits)
// ---------------------------------------------------------------------------

const VERSION_OFFSET: usize = 6;
const CURVE_ID_OFFSET: usize = 7;
const RESERVED_OFFSET: usize = 8;
const AR1CS_BLAKE3_OFFSET: usize = 16;
const VK_BLAKE3_OFFSET: usize = 48;
const AR1CS_BYTE_LEN_OFFSET: usize = 80;
const VK_BYTE_LEN_OFFSET: usize = 88;
const PK_BYTE_LEN_OFFSET: usize = 96;
const HEADER_SIZE: usize = 128;
const TRAILER_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SquareCircuit {
    x: Option<Fr>,
    y: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y_var = cs.new_input_variable(|| Ok(self.y))?;
        cs.enforce_constraint(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var),
            LinearCombination::from(y_var),
        )?;
        Ok(())
    }
}

fn setup_circuit() -> SquareCircuit {
    SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    }
}

fn extract_arcs() -> ArcsFile<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    setup_circuit().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices)
}

fn make_valid_file_bytes() -> Vec<u8> {
    let mut rng = ark_std::test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng,
    )
    .unwrap();
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(extract_arcs(), pk);
    let mut buf = Vec::new();
    arzkey.write(&mut buf).unwrap();
    buf
}

fn recompute_trailer(buf: &mut [u8]) {
    let len = buf.len();
    let body_len = len - TRAILER_LEN;
    let hash = blake3::hash(&buf[..body_len]);
    buf[body_len..].copy_from_slice(hash.as_bytes());
}

fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Header-level rejects
// ---------------------------------------------------------------------------

#[test]
fn rejects_bad_magic() {
    let mut buf = make_valid_file_bytes();
    buf[0] = 0xFF;
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected BadMagic");
    assert!(matches!(err, ArzkeyError::BadMagic), "got: {err:?}");
}

#[test]
fn rejects_unsupported_version() {
    let mut buf = make_valid_file_bytes();
    buf[VERSION_OFFSET] = 0x01;
    recompute_trailer(&mut buf);
    let err =
        ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected UnsupportedVersion");
    assert!(
        matches!(err, ArzkeyError::UnsupportedVersion(0x01)),
        "got: {err:?}"
    );
}

#[test]
fn rejects_non_zero_reserved() {
    let mut buf = make_valid_file_bytes();
    buf[RESERVED_OFFSET] = 0x01;
    recompute_trailer(&mut buf);
    let err =
        ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected ReservedNotZero");
    assert!(matches!(err, ArzkeyError::ReservedNotZero), "got: {err:?}");
}

#[test]
fn rejects_curve_mismatch() {
    // Outer header curve_id = Bls12_381 (0x02), embedded arcs.curve_id =
    // Bn254 (0x01) → CurveMismatch fires from validate() at the end of read.
    let mut buf = make_valid_file_bytes();
    buf[CURVE_ID_OFFSET] = 0x02;
    recompute_trailer(&mut buf);
    let err =
        ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected CurveMismatch");
    assert!(
        matches!(
            err,
            ArzkeyError::CurveMismatch {
                header: 0x02,
                embedded: 0x01,
            }
        ),
        "got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Length / blake3 mismatches
// ---------------------------------------------------------------------------

#[test]
fn rejects_ar1cs_length_mismatch() {
    let mut buf = make_valid_file_bytes();
    let body_remaining = (buf.len() - TRAILER_LEN - HEADER_SIZE) as u64;
    let bogus = body_remaining + 1000;
    buf[AR1CS_BYTE_LEN_OFFSET..AR1CS_BYTE_LEN_OFFSET + 8].copy_from_slice(&bogus.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice())
        .expect_err("expected Ar1csLengthMismatch");
    assert!(
        matches!(err, ArzkeyError::Ar1csLengthMismatch { .. }),
        "got: {err:?}"
    );
}

#[test]
fn rejects_vk_length_mismatch() {
    // Set vk_byte_len > body bytes remaining after the embedded ar1cs section
    // (but well below MAX_ARZKEY_BYTES so the OOM guard does not fire first).
    let mut buf = make_valid_file_bytes();
    let ar1cs_byte_len = read_u64_le(&buf, AR1CS_BYTE_LEN_OFFSET);
    let body_after_ar1cs = (buf.len() - TRAILER_LEN - HEADER_SIZE) as u64 - ar1cs_byte_len;
    let bogus = body_after_ar1cs + 100;
    buf[VK_BYTE_LEN_OFFSET..VK_BYTE_LEN_OFFSET + 8].copy_from_slice(&bogus.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice())
        .expect_err("expected VkLengthMismatch");
    assert!(
        matches!(err, ArzkeyError::VkLengthMismatch { .. }),
        "got: {err:?}"
    );
}

#[test]
fn rejects_pk_length_mismatch() {
    // pk_byte_len > body bytes remaining after ar1cs and vk sections.
    let mut buf = make_valid_file_bytes();
    let ar1cs_byte_len = read_u64_le(&buf, AR1CS_BYTE_LEN_OFFSET);
    let vk_byte_len = read_u64_le(&buf, VK_BYTE_LEN_OFFSET);
    let pk_remaining = (buf.len() - TRAILER_LEN - HEADER_SIZE) as u64
        - ar1cs_byte_len
        - vk_byte_len;
    let bogus = pk_remaining + 100;
    buf[PK_BYTE_LEN_OFFSET..PK_BYTE_LEN_OFFSET + 8].copy_from_slice(&bogus.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice())
        .expect_err("expected PkLengthMismatch");
    assert!(
        matches!(err, ArzkeyError::PkLengthMismatch { .. }),
        "got: {err:?}"
    );
}

#[test]
fn rejects_ar1cs_blake3_mismatch() {
    let mut buf = make_valid_file_bytes();
    buf[AR1CS_BLAKE3_OFFSET] ^= 0x01;
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice())
        .expect_err("expected Ar1csBlake3Mismatch");
    assert!(
        matches!(err, ArzkeyError::Ar1csBlake3Mismatch),
        "got: {err:?}"
    );
}

#[test]
fn rejects_vk_blake3_mismatch() {
    let mut buf = make_valid_file_bytes();
    buf[VK_BLAKE3_OFFSET] ^= 0x01;
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice())
        .expect_err("expected VkBlake3Mismatch");
    assert!(matches!(err, ArzkeyError::VkBlake3Mismatch), "got: {err:?}");
}

// ---------------------------------------------------------------------------
// VkDuplicationDrift (OV-2)
// ---------------------------------------------------------------------------

/// Build a hybrid `.arzkey` whose vk_section is from setup #1 but whose
/// pk_section (containing pk.vk) is from setup #2 of the same circuit.
/// On read, `pk.vk != vk_section` → VkDuplicationDrift. This is the
/// structural check that the OV-2 plan demands.
#[test]
fn rejects_vk_duplication_drift() {
    let mut rng1 = StdRng::from_seed([1u8; 32]);
    let pk1 = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng1,
    )
    .unwrap();
    let arzkey1 = ArzkeyFile::<Bn254>::from_setup_output(extract_arcs(), pk1);
    let mut buf = Vec::new();
    arzkey1.write(&mut buf).unwrap();

    let mut rng2 = StdRng::from_seed([2u8; 32]);
    let pk2 = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng2,
    )
    .unwrap();
    assert_ne!(pk2.vk, arzkey1.vk, "two ceremonies must produce distinct VKs");

    let mut pk2_bytes = Vec::new();
    pk2.serialize_compressed(&mut pk2_bytes).unwrap();

    let ar1cs_byte_len = read_u64_le(&buf, AR1CS_BYTE_LEN_OFFSET);
    let vk_byte_len = read_u64_le(&buf, VK_BYTE_LEN_OFFSET);
    let pk_byte_len = read_u64_le(&buf, PK_BYTE_LEN_OFFSET);
    assert_eq!(
        pk_byte_len, pk2_bytes.len() as u64,
        "PK serialization size must match for byte-level swap"
    );

    let pk_start = HEADER_SIZE + ar1cs_byte_len as usize + vk_byte_len as usize;
    let pk_end = pk_start + pk_byte_len as usize;
    buf[pk_start..pk_end].copy_from_slice(&pk2_bytes);
    recompute_trailer(&mut buf);

    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice())
        .expect_err("expected VkDuplicationDrift");
    assert!(
        matches!(err, ArzkeyError::VkDuplicationDrift),
        "got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Trailer-level rejects
// ---------------------------------------------------------------------------

#[test]
fn rejects_corrupted_trailer() {
    let mut buf = make_valid_file_bytes();
    let last = buf.len() - 1;
    buf[last] ^= 0xFF;
    let err =
        ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected ChecksumMismatch");
    assert!(matches!(err, ArzkeyError::ChecksumMismatch), "got: {err:?}");
}

#[test]
fn rejects_trailing_bytes() {
    // Insert 16 bytes between PK end and the trailer, recompute trailer.
    // ChecksumMismatch passes; pk_end != body.len() at the end of read →
    // TrailingBytes(16).
    let mut buf = make_valid_file_bytes();
    let trailer_pos = buf.len() - TRAILER_LEN;
    let trailer: Vec<u8> = buf[trailer_pos..].to_vec();
    buf.truncate(trailer_pos);
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&trailer);
    recompute_trailer(&mut buf);
    let err =
        ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected TrailingBytes");
    assert!(matches!(err, ArzkeyError::TrailingBytes(16)), "got: {err:?}");
}

// ---------------------------------------------------------------------------
// OOM guards (TEST-3)
// ---------------------------------------------------------------------------

#[test]
fn rejects_oversize_ar1cs_byte_len() {
    let mut buf = make_valid_file_bytes();
    buf[AR1CS_BYTE_LEN_OFFSET..AR1CS_BYTE_LEN_OFFSET + 8]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected FileTooLarge");
    assert!(matches!(err, ArzkeyError::FileTooLarge), "got: {err:?}");
}

#[test]
fn rejects_oversize_vk_byte_len() {
    let mut buf = make_valid_file_bytes();
    buf[VK_BYTE_LEN_OFFSET..VK_BYTE_LEN_OFFSET + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected FileTooLarge");
    assert!(matches!(err, ArzkeyError::FileTooLarge), "got: {err:?}");
}

#[test]
fn rejects_oversize_pk_byte_len() {
    let mut buf = make_valid_file_bytes();
    let bogus = MAX_ARZKEY_BYTES + 1;
    buf[PK_BYTE_LEN_OFFSET..PK_BYTE_LEN_OFFSET + 8].copy_from_slice(&bogus.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect_err("expected FileTooLarge");
    assert!(matches!(err, ArzkeyError::FileTooLarge), "got: {err:?}");
}

// ---------------------------------------------------------------------------
// validate-only
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_count_mismatch() {
    // CountMismatch fires from validate() when the in-memory header's
    // mirrored counts disagree with the embedded arcs header. The read
    // path enforces consistency structurally, so this fires only after
    // manual mutation.
    let mut rng = ark_std::test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng,
    )
    .unwrap();
    let mut arzkey = ArzkeyFile::<Bn254>::from_setup_output(extract_arcs(), pk);
    arzkey.header.num_constraints = 999;

    let err = arzkey.validate().expect_err("expected CountMismatch");
    assert!(
        matches!(
            err,
            ArzkeyError::CountMismatch {
                field: "num_constraints",
                header: 999,
                ..
            }
        ),
        "got: {err:?}"
    );
}
