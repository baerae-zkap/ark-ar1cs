use std::io::{Cursor, Read, Write};

/// Maximum file size accepted by [`ArcsFile::read`].
///
/// Files larger than this limit are rejected with [`ArcsError::FileTooLarge`]
/// before any parsing occurs, preventing unbounded memory allocation from
/// oversized or adversarial inputs.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

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
///
/// # File layout
///
/// ```text
/// [header: 57 bytes]
/// [matrix A: custom serialization]
/// [matrix B: custom serialization]
/// [matrix C: custom serialization]
/// [Blake3 checksum: 32 bytes trailer]
/// ```
///
/// The 32-byte trailer is the Blake3 hash of all preceding bytes (header + matrices).
/// `read` verifies the checksum before parsing. `write` appends it automatically.
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

    /// Serialize header + matrices into a byte vector (no trailer appended).
    ///
    /// Shared helper between `write` and `body_blake3` so both surface the
    /// same canonical bytes.
    fn body_bytes(&self) -> Result<Vec<u8>, ArcsError> {
        let mut body: Vec<u8> = Vec::new();
        self.header.write(&mut body)?;
        write_matrix(&self.a, &mut body)?;
        write_matrix(&self.b, &mut body)?;
        write_matrix(&self.c, &mut body)?;
        Ok(body)
    }

    /// Returns the Blake3 hash of the canonical body bytes
    /// (header + matrix_a + matrix_b + matrix_c, *excluding* the trailer).
    ///
    /// Byte-range diagram (relative to the `.ar1cs` file):
    ///
    /// ```text
    /// [0, HEADER_SIZE)            header
    /// [HEADER_SIZE, A_END)        matrix A   (canonical sort: rows in
    ///                                          order, (coeff, var_idx)
    ///                                          within each row sorted
    ///                                          by var_idx ascending)
    /// [A_END,        B_END)       matrix B   (same canonical sort)
    /// [B_END,        C_END)       matrix C   (same canonical sort)
    /// [C_END,        C_END + 32)  trailer    (Blake3 of [0, C_END));
    ///                                          NOT included in
    ///                                          body_blake3()
    /// ```
    ///
    /// The canonical sort is structurally enforced by `write_matrix`. Two
    /// `ConstraintMatrices` with identical content but reordered
    /// `(coeff, var_idx)` pairs within a row produce byte-identical
    /// `.ar1cs` output and therefore identical `body_blake3()` values.
    ///
    /// This is the same hash that appears in the file's own trailer and
    /// must be embedded in any sibling format that references this file
    /// (`.arzkey`, `.arwtns`).
    pub fn body_blake3(&self) -> [u8; 32] {
        let body = self
            .body_bytes()
            .expect("serializing a constructed ArcsFile to Vec<u8> cannot fail");
        *blake3::hash(&body).as_bytes()
    }

    /// Serialize to `w`, appending a 32-byte Blake3 checksum trailer.
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArcsError> {
        let body = self.body_bytes()?;
        let hash = blake3::hash(&body);
        w.write_all(&body)?;
        w.write_all(hash.as_bytes())?;
        Ok(())
    }

    /// Deserialize from `r`.
    ///
    /// Reads all bytes, verifies the 32-byte Blake3 checksum trailer, then
    /// parses and validates the header + matrices. Bounded allocation:
    /// `read_matrix` rejects files whose row/entry counts exceed the header.
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArcsError> {
        // Read the entire file into memory so we can verify the checksum.
        // Limit reads to MAX_FILE_BYTES to prevent OOM from oversized streams.
        // We read one extra byte: if we get exactly MAX_FILE_BYTES+1 bytes,
        // the file is over the limit and we return FileTooLarge.
        let mut all_bytes = Vec::new();
        r.take(MAX_FILE_BYTES + 1).read_to_end(&mut all_bytes)?;
        if all_bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(ArcsError::FileTooLarge);
        }

        const CHECKSUM_LEN: usize = 32;
        if all_bytes.len() < CHECKSUM_LEN {
            return Err(ArcsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file too short to contain checksum trailer",
            )));
        }

        let (body, stored_hash) = all_bytes.split_at(all_bytes.len() - CHECKSUM_LEN);
        let computed_hash = blake3::hash(body);
        if stored_hash != computed_hash.as_bytes() {
            return Err(ArcsError::ChecksumMismatch);
        }

        // Parse header + matrices from the verified body.
        let mut cursor = Cursor::new(body);
        let header = ArcsHeader::read(&mut cursor)?;
        let a = read_matrix(
            &mut cursor,
            header.num_constraints as usize,
            header.a_non_zero as usize,
        )?;
        let b = read_matrix(
            &mut cursor,
            header.num_constraints as usize,
            header.b_non_zero as usize,
        )?;
        let c = read_matrix(
            &mut cursor,
            header.num_constraints as usize,
            header.c_non_zero as usize,
        )?;

        // Reject files with trailing bytes between the matrices and the checksum.
        // Without this check, two different byte sequences could deserialize to the same
        // ArcsFile, violating the canonical-serialization invariant required for
        // content-addressed ceremony use cases.
        if cursor.position() != body.len() as u64 {
            return Err(ArcsError::ValidationFailed(format!(
                "unexpected trailing bytes: {} byte(s) after matrix data",
                body.len() as u64 - cursor.position(),
            )));
        }

        let file = ArcsFile { header, a, b, c };
        file.validate()?;
        Ok(file)
    }

    /// Check that header counts are consistent with actual matrix dimensions.
    ///
    /// Guards the silent-correctness-bug scenario: if `num_constraints` doesn't
    /// match the matrix row count, arkworks' `generate_parameters` computes the
    /// wrong FFT domain size and produces silently wrong proving keys.
    pub fn validate(&self) -> Result<(), ArcsError> {
        let h = &self.header;

        // The implicit "1" wire at index 0 is always pre-allocated by arkworks.
        if h.num_instance_variables == 0 {
            return Err(ArcsError::ValidationFailed(
                "num_instance_variables must be >= 1 \
                 (implicit \"1\" wire always occupies index 0)"
                    .into(),
            ));
        }

        // Row counts must match num_constraints.
        for (name, matrix) in [("a", &self.a), ("b", &self.b), ("c", &self.c)] {
            if matrix.len() as u64 != h.num_constraints {
                return Err(ArcsError::ValidationFailed(format!(
                    "matrix {name}: expected {rows} rows (num_constraints), got {actual}",
                    rows = h.num_constraints,
                    actual = matrix.len(),
                )));
            }
        }

        // Non-zero entry counts must match header.
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

        // Column indices must be within [0, num_instance_variables + num_witness_variables).
        // An out-of-bounds index would cause the importer to reference an unallocated
        // variable, producing a silently wrong constraint system.
        //
        // Use checked_add: if the sum overflows usize, any column index would trivially
        // pass a saturating bound (saturating to usize::MAX), defeating the check entirely.
        let max_col = (h.num_instance_variables as usize)
            .checked_add(h.num_witness_variables as usize)
            .ok_or_else(|| {
                ArcsError::ValidationFailed(
                    "num_instance_variables + num_witness_variables overflows usize".into(),
                )
            })?;
        for (name, matrix) in [("a", &self.a), ("b", &self.b), ("c", &self.c)] {
            for row in matrix {
                for (_coeff, col) in row {
                    if *col >= max_col {
                        return Err(ArcsError::ValidationFailed(format!(
                            "matrix {name}: col {col} out of bounds (max {max_col})"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}
