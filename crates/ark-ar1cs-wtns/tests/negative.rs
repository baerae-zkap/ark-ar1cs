/// `.arwtns` negative tests — every malformed scenario asserts a distinct
/// structured `ArwtnsError` variant via exact-match on the variant (CQ-4),
/// not on a string. Includes pre-allocation OOM guards (TEST-3).
use ark_ar1cs_format::{ArcsError, CurveId};
use ark_ar1cs_wtns::{ArwtnsError, ArwtnsFile, ARWTNS_HEADER_SIZE, MAX_ARWTNS_BYTES};
use ark_bn254::Fr;

const NUM_INSTANCE_OFFSET: usize = ARWTNS_HEADER_SIZE - 16;
const TRAILER_LEN: usize = 32;

/// Build a small valid `.arwtns` file (2 instance, 3 witness for Bn254) and
/// return its raw bytes. Tests then mutate specific bytes and recompute the
/// trailer to drill past `ChecksumMismatch` into the variant under test.
fn make_valid_file() -> Vec<u8> {
    let f = ArwtnsFile::<Fr>::from_assignments(
        CurveId::Bn254,
        [42u8; 32],
        &[Fr::from(1u64), Fr::from(2u64)],
        &[Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)],
    );
    let mut buf = Vec::new();
    f.write(&mut buf).unwrap();
    buf
}

fn recompute_trailer(buf: &mut [u8]) {
    let len = buf.len();
    let body_len = len - TRAILER_LEN;
    let hash = blake3::hash(&buf[..body_len]);
    buf[body_len..].copy_from_slice(hash.as_bytes());
}

#[test]
fn rejects_bad_magic() {
    let mut buf = make_valid_file();
    buf[0] = 0xFF;
    recompute_trailer(&mut buf);
    let err = ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect_err("expected BadMagic");
    assert!(matches!(err, ArwtnsError::BadMagic), "got: {err:?}");
}

#[test]
fn rejects_unsupported_version() {
    let mut buf = make_valid_file();
    buf[6] = 0x01;
    recompute_trailer(&mut buf);
    let err =
        ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect_err("expected UnsupportedVersion");
    assert!(
        matches!(err, ArwtnsError::UnsupportedVersion(0x01)),
        "got: {err:?}"
    );
}

#[test]
fn rejects_unsupported_curve() {
    let mut buf = make_valid_file();
    buf[7] = 0xFF;
    recompute_trailer(&mut buf);
    let err =
        ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect_err("expected unsupported curve");
    assert!(
        matches!(err, ArwtnsError::Format(ArcsError::UnsupportedCurve(0xFF))),
        "got: {err:?}"
    );
}

#[test]
fn rejects_non_zero_reserved() {
    let mut buf = make_valid_file();
    buf[8] = 0x01; // first byte of reserved[8]
    recompute_trailer(&mut buf);
    let err =
        ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect_err("expected ReservedNotZero");
    assert!(matches!(err, ArwtnsError::ReservedNotZero), "got: {err:?}");
}

#[test]
fn rejects_corrupted_trailer() {
    let mut buf = make_valid_file();
    let last = buf.len() - 1;
    buf[last] ^= 0xFF;
    let err =
        ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect_err("expected ChecksumMismatch");
    assert!(matches!(err, ArwtnsError::ChecksumMismatch), "got: {err:?}");
}

#[test]
fn rejects_oversize_file() {
    // Feed MAX_ARWTNS_BYTES + 1 zero bytes through a streaming reader. The
    // inner `r.take(MAX+1).read_to_end` reads MAX+1 bytes, then the
    // `> MAX` check fires before any further parsing.
    use std::io::Read;
    let mut r = std::io::repeat(0u8).take(MAX_ARWTNS_BYTES + 1);
    let err = ArwtnsFile::<Fr>::read(&mut r).expect_err("expected FileTooLarge");
    assert!(matches!(err, ArwtnsError::FileTooLarge), "got: {err:?}");
}

#[test]
fn rejects_oversize_counts_before_alloc() {
    // TEST-3: num_instance = u64::MAX overflows checked_add(num_witness)
    // → reader returns FileTooLarge BEFORE any Vec::with_capacity.
    let mut buf = make_valid_file();
    buf[NUM_INSTANCE_OFFSET..NUM_INSTANCE_OFFSET + 8]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    recompute_trailer(&mut buf);
    let err =
        ArwtnsFile::<Fr>::read(&mut buf.as_slice()).expect_err("expected FileTooLarge");
    assert!(matches!(err, ArwtnsError::FileTooLarge), "got: {err:?}");
}

#[test]
fn rejects_counts_exceeding_stream_remaining() {
    // Header claims 100 instance elements, body only has 5 elements total.
    // Reader rejects with BodyLengthMismatch BEFORE allocating Vec<F>.
    let mut buf = make_valid_file();
    buf[NUM_INSTANCE_OFFSET..NUM_INSTANCE_OFFSET + 8]
        .copy_from_slice(&100u64.to_le_bytes());
    recompute_trailer(&mut buf);
    let err = ArwtnsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("expected BodyLengthMismatch");
    assert!(
        matches!(err, ArwtnsError::BodyLengthMismatch { .. }),
        "got: {err:?}"
    );
}

#[test]
fn rejects_extra_body_bytes() {
    // Insert 32 padding bytes between body end and trailer; recompute
    // trailer so ChecksumMismatch passes. Header counts say body is
    // shorter than what the stream contains → BodyLengthMismatch.
    let mut buf = make_valid_file();
    let trailer_pos = buf.len() - TRAILER_LEN;
    let trailer: Vec<u8> = buf[trailer_pos..].to_vec();
    buf.truncate(trailer_pos);
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&trailer);
    recompute_trailer(&mut buf);
    let err = ArwtnsFile::<Fr>::read(&mut buf.as_slice())
        .expect_err("expected BodyLengthMismatch");
    assert!(
        matches!(err, ArwtnsError::BodyLengthMismatch { .. }),
        "got: {err:?}"
    );
}

#[test]
fn validate_rejects_count_mismatch() {
    // CountMismatch fires from validate() when the in-memory Vec length
    // disagrees with the header. The read path enforces consistency
    // structurally, so this only fires on manual mutation.
    let blake3 = [0u8; 32];
    let mut f = ArwtnsFile::<Fr>::from_assignments(
        CurveId::Bn254,
        blake3,
        &[Fr::from(1u64)],
        &[Fr::from(2u64)],
    );
    f.header.num_instance = 99;
    let err = f.validate().expect_err("expected CountMismatch");
    assert!(
        matches!(
            err,
            ArwtnsError::CountMismatch {
                field: "num_instance",
                header: 99,
                actual: 1,
            }
        ),
        "got: {err:?}"
    );
}
