# Changelog

All notable changes to the ark-ar1cs workspace are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

> No version label yet. The breaking / removed entries below land
> together across the feature-boundary migration (Commits 2–7); a
> version label is assigned at release-cut time, not here.

### Breaking
- **`prove` signature redesigned.**
  `prove(&ArzkeyFile<E>, &[E::ScalarField], &mut R)` →
  `prove<E, R>(&ProvingKey<E>, &ArcsFile<E::ScalarField>, &[E::ScalarField], &mut R)`.
  Caller now supplies `pk` and `arcs` directly, both retrieved via
  arkworks `CanonicalSerialize` / the `.ar1cs` codec respectively.
  `ProverError` shrinks to 4 variants
  (`WitnessLengthMismatch`, `AssignmentNotSatisfying { row }`,
  `Groth16`, `SerializationError`); identity binding is now the
  caller's responsibility — see
  `docs/artifact-trust-boundary.md`.
- **`synthesize_full_assignment` / `WitnessError` moved to core.**
  `ark_ar1cs_wasm_witness::synthesize_full_assignment` →
  `ark_ar1cs::synthesize_full_assignment` (also
  `ark_ar1cs::witness::synthesize_full_assignment`). Same for
  `WitnessError`. `impl From<WitnessError> for WitnessAbiCode` is
  removed (no wasm ABI dependency in core).
- **Curve mismatch is now a type error.** `prove` no longer carries a
  runtime `ArtifactMismatchReason::CurveId` arm; mismatched curves
  (`ProvingKey<Bn254>` + `ArcsFile<<Bls12_381 as Pairing>::ScalarField>`)
  fail to compile. The previous runtime check is unreachable in the new
  signature.

### Removed
- **`.arzkey` envelope (`ark_ar1cs::arzkey::*`).** Entire module
  (`ArzkeyFile`, `ArzkeyHeader`, `ArzkeyError`, `MAX_ARZKEY_BYTES`,
  `ARZKEY_*` constants) deleted. Setup-output bundling is a deployment
  packaging decision; callers distribute `pk` and `.ar1cs` separately
  and bind via `arcs.body_blake3()` in their manifest. Examples
  (`02_round_trip_arzkey.rs`, `04_wrap_pk_into_arzkey.rs`) and tests
  (`arzkey_round_trip.rs`, `arzkey_negative.rs`,
  `arzkey_partial_read.rs`) deleted.
- **`ark_ar1cs::verify` wrapper.** Caller now calls
  `Groth16::verify_proof(&prepare_verifying_key(&pk.vk), &proof, public_inputs)`
  directly.
- **`ark_ar1cs_build::from_setup_output`.** Caller serializes
  `pk` via `CanonicalSerialize` and writes `.ar1cs` via `arcs.write`
  directly; no single-call wrapper.
- **`ProverError::ArtifactMismatch { reason }` + `ArtifactMismatchReason`
  (`CurveId`, `Ar1csBlake3`, `SelfConsistency`, `CountMismatch`).**
  Identity policy is caller-owned; `ProverError::CorruptArtifact` is
  removed as unreachable after the `.arzkey` module deletion.
- **`fast-prove` cargo feature.** The `_unchecked` deserialize trust
  decision is the caller's. Callers that want it call
  `ProvingKey::deserialize_uncompressed_unchecked` directly.
- **`ark-ar1cs-wasm-witness` crate (entire workspace member).**
  `WitnessGenerator` trait, `export_witness_generator!` macro, wasm
  ABI primitives, `WitnessAbiCode`, `witness_generator_native`,
  `packed::*`, `mock::*`, and the `large-witness-fixture` member are
  all deleted. Consumers that need a wasm witness export implement
  their own ABI on top of the now-core
  `synthesize_full_assignment` helper. Associated artifacts
  (`bench-harness/`, `bench-results/`, `dhat-heap.json`) are deleted
  with the crate.

### Changed
- **Workspace consolidated from 8 crates to 5 (prior cycle), then
  to 2 (this cycle).** Final workspace members: `crates/ark-ar1cs`,
  `crates/ark-ar1cs-build`. Earlier-cycle import-path renames
  (`ark_ar1cs_importer::*` → `ark_ar1cs::format::importer::*`,
  `ark_ar1cs_exporter::*` → `ark_ar1cs_build::exporter::*`,
  `ark_ar1cs_test_fixtures::*` → `ark_ar1cs::format::test_fixtures::*`)
  remain in effect. No behavioral change to the codec or example
  byte outputs.
- **`.ar1cs` `MAX_FILE_BYTES` documented as 2 GiB.** README's
  Format envelope table previously listed 256 MiB; the constant in
  `crates/ark-ar1cs/src/format/schema.rs` has been 2 GiB. This
  release synchronizes the documented value with the code. Format
  bytes are unchanged.
- **Workspace lint policy.** `[workspace.lints.rust]
  unsafe_code = "deny"`, `[workspace.lints.clippy] unwrap_used =
  "deny"` apply to all (remaining) members. Test code self-exempts
  via `#![cfg_attr(test, allow(clippy::unwrap_used,
  clippy::expect_used))]` per crate. `rust-version = "1.81"` pinned.

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
