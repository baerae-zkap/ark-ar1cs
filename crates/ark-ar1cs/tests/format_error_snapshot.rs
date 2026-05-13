//! Locks `Display` and `Debug` outputs of `ArcsError` so future drift
//! (variant rename, field reorder, message edit) is caught immediately.
//!
//! Cross-repo (zkap-circuit / zkap-zkp / circuit-agnostic-test) does NOT
//! depend on these strings — confirmed by Stream 2 plan-time grep
//! (`.omc/plans/2026-05-13-stream-2.md` §"사전 작업 4"). The lock is
//! purely an internal regression catch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::error::Error;

use ark_ar1cs::format::{ArcsError, CurveId};

#[test]
fn display_invalid_magic() {
    let e = ArcsError::InvalidMagic;
    assert_eq!(format!("{}", e), "invalid magic bytes");
}

#[test]
fn display_unsupported_version() {
    let e = ArcsError::UnsupportedVersion(0x42);
    assert_eq!(format!("{}", e), "unsupported version: 0x42");
}

#[test]
fn display_unsupported_curve() {
    let e = ArcsError::UnsupportedCurve(0xFF);
    assert_eq!(format!("{}", e), "unsupported curve ID: 0xff");
}

#[test]
fn display_curve_id_mismatch() {
    let e = ArcsError::CurveIdMismatch {
        expected: CurveId::Bn254,
        found: CurveId::Bls12_381,
    };
    assert_eq!(
        format!("{}", e),
        "curve ID mismatch: expected Bn254, found Bls12_381"
    );
}

#[test]
fn display_reserved_not_zero() {
    let e = ArcsError::ReservedNotZero;
    assert_eq!(format!("{}", e), "reserved header byte must be zero");
}

#[test]
fn display_validation_failed() {
    let e = ArcsError::ValidationFailed("constraint 7 unsatisfied".to_string());
    assert_eq!(
        format!("{}", e),
        "validation failed: constraint 7 unsatisfied"
    );
}

#[test]
fn display_checksum_mismatch() {
    let e = ArcsError::ChecksumMismatch;
    assert_eq!(
        format!("{}", e),
        "Blake3 checksum mismatch: file is corrupt"
    );
}

#[test]
fn display_file_too_large() {
    let e = ArcsError::FileTooLarge;
    let s = format!("{}", e);
    assert!(
        s.starts_with("file exceeds maximum allowed size ("),
        "got: {s}"
    );
    assert!(s.ends_with(" MB)"), "got: {s}");
}

#[test]
fn display_serialization_wraps_inner() {
    let inner = ark_serialize::SerializationError::InvalidData;
    let e = ArcsError::Serialization(inner);
    let s = format!("{}", e);
    assert!(s.starts_with("serialization error: "), "got: {s}");
}

#[test]
fn display_io_wraps_inner() {
    let inner = std::io::Error::new(std::io::ErrorKind::Other, "underlying");
    let e = ArcsError::Io(inner);
    assert_eq!(format!("{}", e), "I/O error: underlying");
}

#[test]
fn source_chain_propagates_io() {
    let inner = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "underlying");
    let arcs: ArcsError = inner.into();
    let src = arcs.source().expect("Io variant must forward source");
    let down = src
        .downcast_ref::<std::io::Error>()
        .expect("source is io::Error");
    assert_eq!(down.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn source_chain_propagates_serialization() {
    let inner = ark_serialize::SerializationError::InvalidData;
    let arcs: ArcsError = inner.into();
    let src = arcs.source();
    assert!(src.is_some(), "Serialization variant must forward source");
}

#[test]
fn source_chain_absent_for_unit_variants() {
    let e = ArcsError::InvalidMagic;
    assert!(e.source().is_none(), "unit variants have no source");
}

#[test]
fn debug_format_stable_for_unit_variant() {
    let e = ArcsError::ChecksumMismatch;
    assert_eq!(format!("{:?}", e), "ChecksumMismatch");
}

#[test]
fn from_io_error_conversion_works() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let arcs: ArcsError = io.into();
    assert!(matches!(arcs, ArcsError::Io(_)));
}

#[test]
fn from_serialization_error_conversion_works() {
    let se = ark_serialize::SerializationError::InvalidData;
    let arcs: ArcsError = se.into();
    assert!(matches!(arcs, ArcsError::Serialization(_)));
}
