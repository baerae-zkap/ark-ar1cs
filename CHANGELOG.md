# Changelog

All notable changes to the ark-ar1cs workspace are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.1] - 2026-04-08

### Added
- **Blake3 checksum trailer** — every `.ar1cs` file now ends with a 32-byte Blake3
  hash of the header + matrices. `ArcsFile::read` verifies the checksum before
  parsing; `ArcsFile::write` appends it automatically. Catches bit-flip corruption
  before a wrong file silently produces incorrect proving keys.
- **Curve-ID mismatch guard** — `ImportedCircuit::from_reader` now requires an
  `expected_curve_id: CurveId` parameter. Returns `ArcsError::CurveIdMismatch` if
  the file was produced for a different curve, preventing silent field-element
  misinterpretation.
- **`ark-ar1cs-test-fixtures` crate** — shared `make_test_matrices()` helper used by
  both the format and importer test suites. No more duplicated fixture code.
- **GitHub Actions CI** — `cargo test --all` and `cargo clippy -- -D warnings` run on
  every push and pull request.
- **`#![deny(unsafe_code)]`** on all three library crates.
- **`MAX_FILE_BYTES` constant** (256 MB) exported from `ark-ar1cs-format`.

### Fixed
- **OOM vector in `read_matrix`** — row and entry counts are now validated against
  header bounds before any allocation, preventing crafted files from triggering
  out-of-memory crashes.
- **Column bounds check in `validate()`** — rejects matrix entries whose variable
  index falls outside `[0, num_instance_variables + num_witness_variables)`.
- **`num_instance_variables >= 1` check in `validate()`** — the implicit "1" wire at
  index 0 is always pre-allocated by arkworks; files claiming zero instance variables
  are now rejected.
- **`saturating_add` overflow in column bounds** — replaced with `checked_add` to
  prevent crafted headers from defeating the column bounds check via integer overflow.
- **Trailing bytes rejected** — bytes between the matrices and the checksum trailer
  are now detected and rejected, enforcing canonical serialization.
- **256 MB file size cap** — `ArcsFile::read` limits input via `take(MAX_FILE_BYTES+1)`
  before calling `read_to_end`, preventing OOM from oversized streams.
- **`ExportError::MatricesUnavailable`** replaces the semantically wrong
  `SynthesisError::AssignmentMissing` when `cs.to_matrices()` returns `None`.

### Changed
- **`ImportedCircuit::from_reader` API change** — now takes `expected_curve_id: CurveId`
  as a second argument. Callers must specify the expected curve; the reader returns
  `ArcsError::CurveIdMismatch` if the file doesn't match.
- **`ImportedCircuit` derives `Debug`.**
- **Test count: 9 → 20** — added coverage for all hardened paths: checksum
  corruption, truncated files, ValidationFailed branches, BLS12-381 round-trip,
  curve-ID mismatch, and degenerate variable counts.
