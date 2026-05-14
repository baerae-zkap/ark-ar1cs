use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;

/// Errors returned by [`prove`](crate::prove).
///
/// As of the feature-boundary migration's Commit 4, the four identity-policy
/// variants the prover used to carry (`ArtifactMismatch`, `CorruptArtifact`,
/// and the `ArtifactMismatchReason` companion enum) are removed: identity
/// binding is a caller-side concern, not a prover concern, and the previous
/// runtime arms had no caller in the prove path itself. See
/// `docs/artifact-trust-boundary.md` for the boundary record.
///
/// Marked `#[non_exhaustive]` (CQ-2). Variants are structured (CQ-4) — never
/// `String` payloads — so callers can match exactly on the failure mode and
/// take typed action on it.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    /// Supplied full-assignment slice length does not equal the constraint
    /// system's `num_instance_variables + num_witness_variables`.
    /// Caught O(1) before the R1CS pre-flight runs.
    #[error("witness length mismatch: expected {expected}, got {got}")]
    WitnessLengthMismatch { expected: usize, got: usize },

    /// R1CS pre-flight failed: the witness assignment does not satisfy
    /// `Az[i] * Bz[i] == Cz[i]` at the indicated row (OV-1). Without this
    /// check `Groth16::create_proof_with_reduction_and_matrices` returns an
    /// `Ok(Proof)` that always fails verification.
    #[error("R1CS pre-flight failed: assignment does not satisfy constraint at row {row}")]
    AssignmentNotSatisfying { row: usize },

    /// Forwarded from `ark_groth16::create_proof_with_reduction_and_matrices`.
    #[error(transparent)]
    Groth16(#[from] SynthesisError),

    /// Forwarded from `ark_serialize` (e.g., witness round-trip helpers
    /// inside caller code that compose with `prove`).
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}
