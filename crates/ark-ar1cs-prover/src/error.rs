use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;

/// The reason a `(.arzkey, .arwtns)` pair fails the bind-check stage of
/// [`prove`](crate::prove).
///
/// Each variant corresponds to exactly one of the four bind rules in the
/// prover design (`§3.3` of the plan):
/// 1. `CurveId` — header `curve_id` differs between the two artifacts.
/// 2. `Ar1csBlake3` — circuit-identity hashes differ between the artifacts.
/// 3. `SelfConsistency` — the `.arzkey`'s embedded `.ar1cs` body hash does not
///    match its own header `ar1cs_blake3`.
/// 4. `CountMismatch` — `arwtns.num_instance + arwtns.num_witness` does not
///    equal `arzkey.num_instance_variables - 1 + arzkey.num_witness_variables`.
///
/// Marked `#[non_exhaustive]` (CQ-2) so future rules can be added without a
/// breaking change. Variants are structured (CQ-4) — never `String` payloads —
/// so callers can match exactly on the failure mode.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum ArtifactMismatchReason {
    /// Rule 1 — header `curve_id` differs between artifacts.
    CurveId { arzkey: u8, arwtns: u8 },
    /// Rule 2 — `ar1cs_blake3` differs between artifacts (different circuit).
    Ar1csBlake3,
    /// Rule 3 — `arzkey.arcs().body_blake3()` differs from
    /// `arzkey.header.ar1cs_blake3` (the `.arzkey` is internally inconsistent).
    SelfConsistency,
    /// Rule 4 — instance/witness count sum does not match the constraint
    /// system's variable layout.
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
    /// Cross-binding rejected the artifact pair before any cryptographic
    /// operation. See [`ArtifactMismatchReason`] for the specific rule.
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
