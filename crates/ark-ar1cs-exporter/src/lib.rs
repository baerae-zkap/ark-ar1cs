#![deny(unsafe_code)]

use std::io::Write;

use ark_ar1cs_format::{ArcsError, ArcsFile, CurveId};
use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};

#[derive(Debug)]
pub enum ExportError {
    Synthesis(SynthesisError),
    Format(ArcsError),
    /// `cs.to_matrices()` returned `None`.
    ///
    /// This should not happen when the CS was created in setup mode and
    /// `finalize()` was called — but is handled explicitly rather than panicking.
    MatricesUnavailable,
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Synthesis(e) => write!(f, "synthesis error: {e}"),
            ExportError::Format(e) => write!(f, "format error: {e}"),
            ExportError::MatricesUnavailable => {
                write!(f, "constraint system matrices unavailable after finalization")
            }
        }
    }
}

impl std::error::Error for ExportError {}

impl From<SynthesisError> for ExportError {
    fn from(e: SynthesisError) -> Self {
        ExportError::Synthesis(e)
    }
}

impl From<ArcsError> for ExportError {
    fn from(e: ArcsError) -> Self {
        ExportError::Format(e)
    }
}

/// Synthesize `circuit` in setup mode, extract the finalized constraint
/// matrices, and write them as an `.ar1cs` file to `writer`.
///
/// Mirrors exactly what `ark_groth16::generate_parameters_with_qap` does
/// before calling `QAP::instance_map_with_evaluation`:
///   1. `cs.set_optimization_goal(OptimizationGoal::Constraints)`
///   2. `cs.set_mode(SynthesisMode::Setup)`
///   3. `circuit.generate_constraints(cs)`
///   4. `cs.finalize()`
///   5. `cs.to_matrices()`
pub fn export_circuit<F, C, W>(
    circuit: C,
    curve_id: CurveId,
    writer: &mut W,
) -> Result<(), ExportError>
where
    F: PrimeField,
    C: ConstraintSynthesizer<F>,
    W: Write,
{
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);

    circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    let matrices = cs.to_matrices().ok_or(ExportError::MatricesUnavailable)?;

    let file = ArcsFile::from_matrices(curve_id, &matrices);
    file.write(writer)?;

    Ok(())
}
