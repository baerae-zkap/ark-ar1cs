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
        // Canonical body order: sort (coeff, var_idx) pairs by var_idx ascending
        // within each row so two ConstraintMatrices with semantically-equal
        // content but reordered pairs serialize to byte-identical output. The
        // sort is stable, so equal var_idx entries (which are R1CS-invalid
        // anyway) preserve input order. See ArcsFile::body_blake3 for the
        // canonical body definition.
        let mut sorted: Vec<&(F, usize)> = row.iter().collect();
        sorted.sort_by_key(|(_, var_idx)| *var_idx);
        for (coeff, var_idx) in sorted {
            coeff.serialize_compressed(&mut *w)?;
            w.write_all(&(*var_idx as u64).to_le_bytes())?;
        }
    }
    Ok(())
}

/// Read one R1CS matrix from `r`, validating bounds against header counts
/// before allocating — preventing OOM from crafted files.
///
/// * `expected_rows` — must equal `num_rows` encoded in the stream
/// * `expected_nz`   — the total non-zero entry budget for this matrix
pub fn read_matrix<F: PrimeField, R: Read>(
    r: &mut R,
    expected_rows: usize,
    expected_nz: usize,
) -> Result<Matrix<F>, ArcsError> {
    let mut buf = [0u8; 8];

    r.read_exact(&mut buf)?;
    let num_rows = u64::from_le_bytes(buf) as usize;
    if num_rows != expected_rows {
        return Err(ArcsError::ValidationFailed(format!(
            "expected {expected_rows} rows, found {num_rows}"
        )));
    }

    let mut matrix = Vec::with_capacity(num_rows);
    let mut total_entries: usize = 0;

    for _ in 0..num_rows {
        r.read_exact(&mut buf)?;
        let num_entries = u64::from_le_bytes(buf) as usize;

        // Budget check: reject before allocating if this row would exceed budget.
        total_entries = total_entries.checked_add(num_entries).ok_or_else(|| {
            ArcsError::ValidationFailed("non-zero entry count overflow".into())
        })?;
        if total_entries > expected_nz {
            return Err(ArcsError::ValidationFailed(format!(
                "non-zero entries exceed header count {expected_nz}"
            )));
        }

        let mut row = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            let coeff = F::deserialize_compressed(&mut *r)?;
            r.read_exact(&mut buf)?;
            let var_idx = u64::from_le_bytes(buf) as usize;
            row.push((coeff, var_idx));
        }
        matrix.push(row);
    }

    if total_entries != expected_nz {
        return Err(ArcsError::ValidationFailed(format!(
            "expected {expected_nz} non-zero entries, found {total_entries}"
        )));
    }

    Ok(matrix)
}
