use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;

/// Why an `ArzkeyFile` is incompatible with the caller's expectations.
///
/// As of Stream 1 PR 1.0 [`prove`](crate::prove) no longer performs binding
/// checks automatically. The variants are kept for callers that *do* their
/// own binding (see the one-line pattern at the crate-root doc) and want a
/// typed error to return:
///
/// ```rust,ignore
/// if arzkey.header.ar1cs_blake3 != expected_ar1cs_blake3 {
///     return Err(ProverError::ArtifactMismatch {
///         reason: ArtifactMismatchReason::Ar1csBlake3,
///     });
/// }
/// ```
///
/// The four historical rules and their current guarantee paths:
/// 1. `CurveId` — caught by `ArzkeyFile::<E>::read` at parse time (type-level
///    `E` vs `header.curve_id` mismatch); kept here for callers comparing two
///    pre-parsed headers from different sources.
/// 2. `Ar1csBlake3` — caller compares against a known-good blake3 (deployment
///    manifest, etc.).
/// 3. `SelfConsistency` — `ArcsFile::read` validates the embedded body hash
///    against the header at read time; kept here for forward compatibility.
/// 4. `CountMismatch` — [`prove`](crate::prove) auto-emits
///    [`ProverError::WitnessLengthMismatch`] when `full_assignment.len()` is
///    inconsistent with `arzkey.header`; kept here for callers that compare
///    two manifests pre-prove.
///
/// `#[non_exhaustive]` so future variants are non-breaking. Variants stay
/// structured (no `String` payloads) so callers can match exactly.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum ArtifactMismatchReason {
    /// Header `curve_id` differs between two artifacts (e.g. an arzkey and a
    /// manifest entry). `ArzkeyFile::<E>::read` already rejects wrong-curve
    /// arzkeys at parse time, so this is for caller-side cross-checks.
    CurveId { arzkey: u8, arwtns: u8 },
    /// `ar1cs_blake3` differs from the caller's expected value (different
    /// circuit). The recommended caller binding check emits this.
    Ar1csBlake3,
    /// An `.arzkey`'s embedded `.ar1cs` body hash does not match its own header
    /// `ar1cs_blake3`. `ArcsFile::read` validates this at read time; kept here
    /// for callers that want to surface the failure as a `ProverError`.
    SelfConsistency,
    /// Instance/witness count sum does not match the constraint system's
    /// variable layout. For length checks at prove time, prefer
    /// [`ProverError::WitnessLengthMismatch`] which `prove` auto-emits.
    CountMismatch { expected: u64, got: u64 },
}

/// Errors returned by [`prove`](crate::prove) and [`verify`](crate::verify).
///
/// Marked `#[non_exhaustive]` (CQ-2). Variants are structured (CQ-4) — never
/// `String` payloads — so callers can match exactly on the failure mode and
/// take typed action on it.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    /// Caller-emitted: the supplied artifact is not the one this prove call
    /// expects. [`prove`](crate::prove) never raises this itself (binding is
    /// a caller responsibility); it is surfaced so caller binding checks
    /// (typically a one-line `ar1cs_blake3` compare) can return a typed error
    /// instead of inventing their own enum.
    #[error("artifact mismatch: {reason:?}")]
    ArtifactMismatch { reason: ArtifactMismatchReason },

    /// R1CS pre-flight failed: the witness assignment does not satisfy
    /// `Az[i] * Bz[i] == Cz[i]` at the indicated row (OV-1). Without this
    /// check `Groth16::create_proof_with_reduction_and_matrices` returns an
    /// `Ok(Proof)` that always fails verification — the worst kind of
    /// footgun in a SNARK toolkit.
    #[error("R1CS pre-flight failed: assignment does not satisfy constraint at row {row}")]
    AssignmentNotSatisfying { row: usize },

    /// An internal invariant on a loaded artifact was violated. Should not be
    /// reachable for files produced by `read`/`from_setup_output` because both
    /// run the appropriate validate() pass; surfaced for forward-compat.
    #[error("corrupt artifact (internal invariant violated)")]
    CorruptArtifact,

    /// Reconstructed full assignment length does not match what the proving
    /// key expects. Distinct from [`ArtifactMismatchReason::CountMismatch`]
    /// (which fires before assembly) and from
    /// [`ProverError::AssignmentNotSatisfying`] (which fires after).
    #[error("witness length mismatch: expected {expected}, got {got}")]
    WitnessLengthMismatch { expected: usize, got: usize },

    /// Forwarded from `ark_groth16::create_proof_with_reduction_and_matrices`
    /// or `Groth16::verify_proof`.
    #[error(transparent)]
    Groth16(#[from] SynthesisError),

    /// Forwarded from `ark_serialize`.
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}
