use std::io::{Cursor, Read, Write};

use ark_ar1cs_format::CurveId;
use ark_ff::PrimeField;

use crate::{
    error::ArwtnsError,
    header::{ArwtnsHeader, ARWTNS_HEADER_SIZE, ARWTNS_VERSION_V0},
};

/// Maximum size of an `.arwtns` file accepted by [`ArwtnsFile::read`].
///
/// Files larger than this are rejected with [`ArwtnsError::FileTooLarge`]
/// before any parsing or allocation occurs.
pub const MAX_ARWTNS_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

const TRAILER_LEN: usize = 32;

/// A deserialized `.arwtns` file: header + the public-input and witness
/// assignments for one proof instance.
///
/// The body excludes the implicit `1` wire (variable index 0); the prover
/// reconstructs the full assignment vector via
/// [`ArwtnsFile::full_assignment_with_one_wire`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArwtnsFile<F: PrimeField> {
    pub header: ArwtnsHeader,
    pub instance: Vec<F>,
    pub witness: Vec<F>,
}

impl<F: PrimeField> ArwtnsFile<F> {
    /// Construct from explicit assignments. `instance` MUST exclude the
    /// implicit `1` wire; the prover prepends it during full-assignment
    /// reconstruction.
    pub fn from_assignments(
        curve_id: CurveId,
        ar1cs_blake3: [u8; 32],
        instance: &[F],
        witness: &[F],
    ) -> Self {
        ArwtnsFile {
            header: ArwtnsHeader {
                version: ARWTNS_VERSION_V0,
                curve_id,
                ar1cs_blake3,
                num_instance: instance.len() as u64,
                num_witness: witness.len() as u64,
            },
            instance: instance.to_vec(),
            witness: witness.to_vec(),
        }
    }

    /// Returns `[F::ONE, instance..., witness...]` — the assignment vector
    /// arkworks Groth16 expects (matches the variable-index ordering used by
    /// `ArcsFile::into_matrices`).
    pub fn full_assignment_with_one_wire(&self) -> Vec<F> {
        let mut full = Vec::with_capacity(1 + self.instance.len() + self.witness.len());
        full.push(F::ONE);
        full.extend_from_slice(&self.instance);
        full.extend_from_slice(&self.witness);
        full
    }

    fn body_bytes(&self) -> Result<Vec<u8>, ArwtnsError> {
        let mut body = Vec::new();
        self.header.write(&mut body)?;
        for x in &self.instance {
            x.serialize_compressed(&mut body)?;
        }
        for x in &self.witness {
            x.serialize_compressed(&mut body)?;
        }
        Ok(body)
    }

    /// Serialize to `w`, appending a 32-byte Blake3 checksum trailer over
    /// header + body.
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArwtnsError> {
        let body = self.body_bytes()?;
        let hash = blake3::hash(&body);
        w.write_all(&body)?;
        w.write_all(hash.as_bytes())?;
        Ok(())
    }

    /// Check that header counts match the in-memory vector lengths.
    /// Fires after manual mutation; `read` already enforces consistency.
    pub fn validate(&self) -> Result<(), ArwtnsError> {
        if self.instance.len() as u64 != self.header.num_instance {
            return Err(ArwtnsError::CountMismatch {
                field: "num_instance",
                header: self.header.num_instance,
                actual: self.instance.len() as u64,
            });
        }
        if self.witness.len() as u64 != self.header.num_witness {
            return Err(ArwtnsError::CountMismatch {
                field: "num_witness",
                header: self.header.num_witness,
                actual: self.witness.len() as u64,
            });
        }
        Ok(())
    }

    /// Deserialize from `r`.
    ///
    /// Pre-allocation OOM guard (TEST-3): every header length field is
    /// checked against `MAX_ARWTNS_BYTES` and remaining stream length BEFORE
    /// any `Vec::with_capacity`.
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArwtnsError> {
        let mut all_bytes = Vec::new();
        r.take(MAX_ARWTNS_BYTES + 1).read_to_end(&mut all_bytes)?;
        if all_bytes.len() as u64 > MAX_ARWTNS_BYTES {
            return Err(ArwtnsError::FileTooLarge);
        }
        if all_bytes.len() < ARWTNS_HEADER_SIZE + TRAILER_LEN {
            return Err(ArwtnsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file too short to contain header + trailer",
            )));
        }

        let (body, stored_hash) = all_bytes.split_at(all_bytes.len() - TRAILER_LEN);
        let computed_hash = blake3::hash(body);
        if stored_hash != computed_hash.as_bytes() {
            return Err(ArwtnsError::ChecksumMismatch);
        }

        let mut cursor = Cursor::new(body);
        let header = ArwtnsHeader::read(&mut cursor)?;

        // Pre-allocation OOM guard: confirm (num_instance + num_witness) ×
        // F::compressed_size fits within the cap AND matches the bytes
        // remaining between header end and trailer split.
        let elem_size = F::ZERO.compressed_size() as u64;
        let body_remaining = body.len() as u64 - cursor.position();
        let total_count = header
            .num_instance
            .checked_add(header.num_witness)
            .ok_or(ArwtnsError::FileTooLarge)?;
        let expected_body = total_count
            .checked_mul(elem_size)
            .ok_or(ArwtnsError::FileTooLarge)?;
        if expected_body > MAX_ARWTNS_BYTES {
            return Err(ArwtnsError::FileTooLarge);
        }
        if expected_body != body_remaining {
            return Err(ArwtnsError::BodyLengthMismatch {
                expected: expected_body,
                actual: body_remaining,
            });
        }

        let mut instance = Vec::with_capacity(header.num_instance as usize);
        for _ in 0..header.num_instance {
            instance.push(F::deserialize_compressed(&mut cursor)?);
        }

        let mut witness = Vec::with_capacity(header.num_witness as usize);
        for _ in 0..header.num_witness {
            witness.push(F::deserialize_compressed(&mut cursor)?);
        }

        if cursor.position() != body.len() as u64 {
            return Err(ArwtnsError::TrailingBytes(
                body.len() as u64 - cursor.position(),
            ));
        }

        let file = ArwtnsFile {
            header,
            instance,
            witness,
        };
        file.validate()?;
        Ok(file)
    }
}
