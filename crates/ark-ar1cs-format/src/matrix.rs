/// Serialization helpers for `Matrix<F> = Vec<Vec<(F, usize)>>`.
///
/// Wire format per matrix:
///   num_rows: u64 LE
///   for each row:
///     num_entries: u64 LE
///     for each (coeff, var_idx):
///       coeff: F::compressed_size() bytes (CanonicalSerialize::serialize_compressed)
///       var_idx: u64 LE
use std::io::{Read, Write};

use ark_ff::PrimeField;

use crate::error::ArcsError;

pub type Matrix<F> = Vec<Vec<(F, usize)>>;

pub fn write_matrix<F: PrimeField, W: Write>(
    matrix: &Matrix<F>,
    w: &mut W,
) -> Result<(), ArcsError> {
    w.write_all(&(matrix.len() as u64).to_le_bytes())?;
    for row in matrix {
        w.write_all(&(row.len() as u64).to_le_bytes())?;
        for (coeff, var_idx) in row {
            coeff.serialize_compressed(&mut *w)?;
            w.write_all(&(*var_idx as u64).to_le_bytes())?;
        }
    }
    Ok(())
}

pub fn read_matrix<F: PrimeField, R: Read>(r: &mut R) -> Result<Matrix<F>, ArcsError> {
    let mut buf = [0u8; 8];

    r.read_exact(&mut buf)?;
    let num_rows = u64::from_le_bytes(buf) as usize;

    let mut matrix = Vec::with_capacity(num_rows);
    for _ in 0..num_rows {
        r.read_exact(&mut buf)?;
        let num_entries = u64::from_le_bytes(buf) as usize;

        let mut row = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            let coeff = F::deserialize_compressed(&mut *r)?;
            r.read_exact(&mut buf)?;
            let var_idx = u64::from_le_bytes(buf) as usize;
            row.push((coeff, var_idx));
        }
        matrix.push(row);
    }
    Ok(matrix)
}
