//! Top-level errors emitted by the generic witness layer.

use ark_relations::gr1cs::SynthesisError;

use crate::abi::WitnessAbiCode;

/// Errors raised by [`crate::synthesize_full_assignment`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// `ConstraintSynthesizer::generate_constraints` failed.
    #[error("constraint synthesis failed: {0}")]
    Synthesis(SynthesisError),

    /// `ConstraintSystemRef::borrow` returned `None` (the cs was dropped or
    /// already mutably borrowed). Should not occur for the
    /// fresh-cs-per-call pattern this crate uses.
    #[error("constraint system borrow unavailable")]
    ConstraintSystemUnavailable,

    /// `instance_assignment` was empty — no implicit `1` wire present.
    /// Indicates the circuit synthesizer did not run, since the cs always
    /// pre-seeds index 0 with `F::ONE`.
    #[error("constraint system missing implicit 1-wire at index 0")]
    MissingOneWire,

    /// Witness assignment `Vec<F>` serialization failed downstream.
    #[error("witness serialize: {0}")]
    Serialize(#[from] ark_serialize::SerializationError),
}

impl From<WitnessError> for WitnessAbiCode {
    fn from(err: WitnessError) -> Self {
        match err {
            WitnessError::Synthesis(_) => WitnessAbiCode::CircuitBuildError,
            WitnessError::ConstraintSystemUnavailable => WitnessAbiCode::CircuitBuildError,
            WitnessError::MissingOneWire => WitnessAbiCode::CircuitBuildError,
            WitnessError::Serialize(_) => WitnessAbiCode::CircuitBuildError,
        }
    }
}
