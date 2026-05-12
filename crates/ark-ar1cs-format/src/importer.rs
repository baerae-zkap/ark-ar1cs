use std::io::Read;

use ark_ff::PrimeField;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

use crate::{ArcsError, ArcsFile, CurveId};

/// A Groth16 circuit reconstructed from an `.ar1cs` file.
///
/// Implements [`ConstraintSynthesizer`] so it can be passed directly to
/// `ark_groth16::generate_parameters` in place of the original Rust circuit.
///
/// # Variable allocation call sequence (from design doc)
///
/// 1. `cs.new_input_variable(|| Ok(F::zero()))` × `(num_instance_variables − 1)`
///    — arkworks pre-allocates the implicit "1" wire at index 0; we allocate only
///    the explicit public inputs.
/// 2. `cs.new_witness_variable(|| Ok(F::zero()))` × `num_witness_variables`
/// 3. `cs.enforce_r1cs_constraint(lc_a, lc_b, lc_c)` for every constraint row.
#[derive(Clone, Debug)]
pub struct ImportedCircuit<F: PrimeField> {
    file: ArcsFile<F>,
}

impl<F: PrimeField> ImportedCircuit<F> {
    /// Read an `.ar1cs` file from `r` and verify that its curve ID matches
    /// `expected_curve_id`.
    ///
    /// Returns `ArcsError::CurveIdMismatch` if the file was produced for a
    /// different curve, preventing silent field-element misinterpretation.
    pub fn from_reader<R: Read>(r: &mut R, expected_curve_id: CurveId) -> Result<Self, ArcsError> {
        let file = ArcsFile::read(r)?;
        if file.header.curve_id != expected_curve_id {
            return Err(ArcsError::CurveIdMismatch {
                expected: expected_curve_id,
                found: file.header.curve_id,
            });
        }
        Ok(ImportedCircuit { file })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ImportedCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let num_instance = self.file.header.num_instance_variables as usize;
        let num_witness = self.file.header.num_witness_variables as usize;

        // Allocate explicit public inputs (index 0 = "1" wire is pre-allocated).
        for _ in 0..(num_instance.saturating_sub(1)) {
            let _ = cs.new_input_variable(|| Ok(F::zero()))?;
        }

        // Allocate witness variables.
        for _ in 0..num_witness {
            let _ = cs.new_witness_variable(|| Ok(F::zero()))?;
        }

        // Replay constraints.
        for ((a_row, b_row), c_row) in self
            .file
            .a
            .iter()
            .zip(self.file.b.iter())
            .zip(self.file.c.iter())
        {
            let lc_a = row_to_lc(a_row, num_instance);
            let lc_b = row_to_lc(b_row, num_instance);
            let lc_c = row_to_lc(c_row, num_instance);
            cs.enforce_r1cs_constraint(|| lc_a, || lc_b, || lc_c)?;
        }

        Ok(())
    }
}

/// Map a matrix column index to the corresponding arkworks [`Variable`].
///
/// Column ordering (from `ark_relations::gr1cs::ConstraintMatrices` docs):
///   0                          → `Variable::one()`
///   1 .. num_instance_vars−1   → `Variable::instance(col)`
///   num_instance_vars ..       → `Variable::witness(col − num_instance_vars)`
fn col_to_variable(col: usize, num_instance: usize) -> Variable {
    if col == 0 {
        Variable::one()
    } else if col < num_instance {
        Variable::instance(col)
    } else {
        Variable::witness(col - num_instance)
    }
}

fn row_to_lc<F: PrimeField>(row: &[(F, usize)], num_instance: usize) -> LinearCombination<F> {
    LinearCombination(
        row.iter()
            .map(|(coeff, col)| (*coeff, col_to_variable(*col, num_instance)))
            .collect(),
    )
}
