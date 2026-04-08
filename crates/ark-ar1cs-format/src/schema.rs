use std::io::{Read, Write};

use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintMatrices;

use crate::{
    error::ArcsError,
    header::{ArcsHeader, CurveId, VERSION_V0},
    matrix::{read_matrix, write_matrix, Matrix},
};

/// A deserialized `.ar1cs` file: header + the three R1CS constraint matrices.
///
/// The matrices use the arkworks variable-index ordering:
///   index 0           — the implicit "1" wire (pre-allocated by arkworks)
///   1..num_instance_variables — explicit public inputs
///   num_instance_variables..  — witness variables
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcsFile<F: PrimeField> {
    pub header: ArcsHeader,
    pub a: Matrix<F>,
    pub b: Matrix<F>,
    pub c: Matrix<F>,
}

impl<F: PrimeField> ArcsFile<F> {
    /// Construct from an arkworks `ConstraintMatrices` and a curve identifier.
    pub fn from_matrices(curve_id: CurveId, matrices: &ConstraintMatrices<F>) -> Self {
        ArcsFile {
            header: ArcsHeader {
                version: VERSION_V0,
                curve_id,
                num_instance_variables: matrices.num_instance_variables as u64,
                num_witness_variables: matrices.num_witness_variables as u64,
                num_constraints: matrices.num_constraints as u64,
                a_non_zero: matrices.a_num_non_zero as u64,
                b_non_zero: matrices.b_num_non_zero as u64,
                c_non_zero: matrices.c_num_non_zero as u64,
            },
            a: matrices.a.clone(),
            b: matrices.b.clone(),
            c: matrices.c.clone(),
        }
    }

    /// Convert back into an arkworks `ConstraintMatrices`.
    pub fn into_matrices(self) -> ConstraintMatrices<F> {
        ConstraintMatrices {
            num_instance_variables: self.header.num_instance_variables as usize,
            num_witness_variables: self.header.num_witness_variables as usize,
            num_constraints: self.header.num_constraints as usize,
            a_num_non_zero: self.header.a_non_zero as usize,
            b_num_non_zero: self.header.b_non_zero as usize,
            c_num_non_zero: self.header.c_non_zero as usize,
            a: self.a,
            b: self.b,
            c: self.c,
        }
    }

    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArcsError> {
        self.header.write(w)?;
        write_matrix(&self.a, w)?;
        write_matrix(&self.b, w)?;
        write_matrix(&self.c, w)?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArcsError> {
        let header = ArcsHeader::read(r)?;
        let a = read_matrix(r)?;
        let b = read_matrix(r)?;
        let c = read_matrix(r)?;
        let file = ArcsFile { header, a, b, c };
        file.validate()?;
        Ok(file)
    }

    /// Checks that header counts are consistent with the actual matrix dimensions.
    ///
    /// This catches the silent-correctness-bug scenario: if the header's
    /// `num_constraints` doesn't match the number of matrix rows, arkworks'
    /// `generate_parameters` will compute the wrong FFT domain size.
    pub fn validate(&self) -> Result<(), ArcsError> {
        let h = &self.header;

        // Row counts must match num_constraints
        for (name, matrix) in [("a", &self.a), ("b", &self.b), ("c", &self.c)] {
            if matrix.len() as u64 != h.num_constraints {
                return Err(ArcsError::ValidationFailed(format!(
                    "matrix {name}: expected {rows} rows (num_constraints), got {actual}",
                    rows = h.num_constraints,
                    actual = matrix.len(),
                )));
            }
        }

        // Non-zero entry counts must match header
        let a_nz = self.a.iter().map(|r| r.len() as u64).sum::<u64>();
        let b_nz = self.b.iter().map(|r| r.len() as u64).sum::<u64>();
        let c_nz = self.c.iter().map(|r| r.len() as u64).sum::<u64>();

        if a_nz != h.a_non_zero {
            return Err(ArcsError::ValidationFailed(format!(
                "a_non_zero: header says {}, matrices have {a_nz}",
                h.a_non_zero
            )));
        }
        if b_nz != h.b_non_zero {
            return Err(ArcsError::ValidationFailed(format!(
                "b_non_zero: header says {}, matrices have {b_nz}",
                h.b_non_zero
            )));
        }
        if c_nz != h.c_non_zero {
            return Err(ArcsError::ValidationFailed(format!(
                "c_non_zero: header says {}, matrices have {c_nz}",
                h.c_non_zero
            )));
        }

        Ok(())
    }
}
