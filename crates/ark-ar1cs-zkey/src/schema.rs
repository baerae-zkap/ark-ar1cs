use std::io::{Cursor, Read, Write};

use ark_ar1cs_format::ArcsFile;
use ark_ec::pairing::Pairing;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    error::ArzkeyError,
    header::{ArzkeyHeader, ARZKEY_HEADER_SIZE, ARZKEY_VERSION_V0},
};

/// Maximum size of an `.arzkey` file accepted by [`ArzkeyFile::read`].
pub const MAX_ARZKEY_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

const TRAILER_LEN: usize = 32;

/// A deserialized `.arzkey` file: the embedded constraint system, the
/// verifying key, and the proving key together as the atomic Groth16 setup
/// output for one circuit.
///
/// Body layout: `ar1cs → vk → pk` (per plan §3.1). VK appears before PK so a
/// partial-read client can fetch `[0, HEADER_SIZE + ar1cs_byte_len + vk_byte_len)`
/// to extract the verifying key without downloading the multi-hundred-MB PK
/// tail.
#[derive(Debug)]
pub struct ArzkeyFile<E: Pairing> {
    pub header: ArzkeyHeader,
    pub arcs: ArcsFile<E::ScalarField>,
    pub vk: VerifyingKey<E>,
    pub pk: ProvingKey<E>,
}

impl<E: Pairing> ArzkeyFile<E> {
    /// Atomic constructor — `vk` is derived from `pk.vk.clone()` so PK/VK
    /// drift inside a single `.arzkey` is structurally impossible (ARCH-3).
    /// Caller cannot supply a `vk` that disagrees with `pk.vk`.
    pub fn from_setup_output(arcs: ArcsFile<E::ScalarField>, pk: ProvingKey<E>) -> Self {
        let curve_id = arcs.header.curve_id;
        let num_instance_variables = arcs.header.num_instance_variables;
        let num_witness_variables = arcs.header.num_witness_variables;
        let num_constraints = arcs.header.num_constraints;
        let ar1cs_blake3 = arcs.body_blake3();

        let mut arcs_bytes = Vec::new();
        arcs.write(&mut arcs_bytes)
            .expect("ArcsFile write to Vec cannot fail");
        let ar1cs_byte_len = arcs_bytes.len() as u64;

        let vk = pk.vk.clone();
        let vk_byte_len = vk.compressed_size() as u64;
        let mut vk_bytes = Vec::with_capacity(vk_byte_len as usize);
        vk.serialize_compressed(&mut vk_bytes)
            .expect("VerifyingKey serialize to Vec cannot fail");
        let vk_blake3 = *blake3::hash(&vk_bytes).as_bytes();

        let pk_byte_len = pk.compressed_size() as u64;

        let header = ArzkeyHeader {
            version: ARZKEY_VERSION_V0,
            curve_id,
            ar1cs_blake3,
            vk_blake3,
            ar1cs_byte_len,
            vk_byte_len,
            pk_byte_len,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        };

        ArzkeyFile {
            header,
            arcs,
            vk,
            pk,
        }
    }

    pub fn vk(&self) -> &VerifyingKey<E> {
        &self.vk
    }

    pub fn pk(&self) -> &ProvingKey<E> {
        &self.pk
    }

    pub fn arcs(&self) -> &ArcsFile<E::ScalarField> {
        &self.arcs
    }

    fn body_bytes(&self) -> Result<Vec<u8>, ArzkeyError> {
        let mut body = Vec::new();
        self.header.write(&mut body)?;
        self.arcs.write(&mut body)?;
        self.vk.serialize_compressed(&mut body)?;
        self.pk.serialize_compressed(&mut body)?;
        Ok(body)
    }

    /// Serialize to `w`, appending a 32-byte Blake3 checksum trailer over
    /// header + body.
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArzkeyError> {
        let body = self.body_bytes()?;
        let hash = blake3::hash(&body);
        w.write_all(&body)?;
        w.write_all(hash.as_bytes())?;
        Ok(())
    }

    /// Cross-validate the in-memory header against the embedded ArcsFile
    /// and the VK duplication invariant. The read path runs `validate`
    /// last, so loaded files satisfy these structurally.
    pub fn validate(&self) -> Result<(), ArzkeyError> {
        if (self.arcs.header.curve_id as u8) != (self.header.curve_id as u8) {
            return Err(ArzkeyError::CurveMismatch {
                header: self.header.curve_id as u8,
                embedded: self.arcs.header.curve_id as u8,
            });
        }
        if self.arcs.header.num_instance_variables != self.header.num_instance_variables {
            return Err(ArzkeyError::CountMismatch {
                field: "num_instance_variables",
                header: self.header.num_instance_variables,
                actual: self.arcs.header.num_instance_variables,
            });
        }
        if self.arcs.header.num_witness_variables != self.header.num_witness_variables {
            return Err(ArzkeyError::CountMismatch {
                field: "num_witness_variables",
                header: self.header.num_witness_variables,
                actual: self.arcs.header.num_witness_variables,
            });
        }
        if self.arcs.header.num_constraints != self.header.num_constraints {
            return Err(ArzkeyError::CountMismatch {
                field: "num_constraints",
                header: self.header.num_constraints,
                actual: self.arcs.header.num_constraints,
            });
        }
        if self.pk.vk != self.vk {
            return Err(ArzkeyError::VkDuplicationDrift);
        }
        Ok(())
    }

    /// Deserialize from `r`.
    ///
    /// Pre-allocation OOM guards (TEST-3): every header length field is
    /// validated against `MAX_ARZKEY_BYTES` and against the remaining body
    /// length BEFORE any per-section deserialization is attempted.
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArzkeyError> {
        let mut all_bytes = Vec::new();
        r.take(MAX_ARZKEY_BYTES + 1).read_to_end(&mut all_bytes)?;
        if all_bytes.len() as u64 > MAX_ARZKEY_BYTES {
            return Err(ArzkeyError::FileTooLarge);
        }
        if all_bytes.len() < ARZKEY_HEADER_SIZE + TRAILER_LEN {
            return Err(ArzkeyError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file too short to contain header + trailer",
            )));
        }

        let (body, stored_hash) = all_bytes.split_at(all_bytes.len() - TRAILER_LEN);
        if blake3::hash(body).as_bytes() != stored_hash {
            return Err(ArzkeyError::ChecksumMismatch);
        }

        let mut cursor = Cursor::new(body);
        let header = ArzkeyHeader::read(&mut cursor)?;

        // OOM guards (TEST-3): each section length must fit within the cap
        // and the running sum must not overflow before we slice the body.
        if header.ar1cs_byte_len > MAX_ARZKEY_BYTES
            || header.vk_byte_len > MAX_ARZKEY_BYTES
            || header.pk_byte_len > MAX_ARZKEY_BYTES
        {
            return Err(ArzkeyError::FileTooLarge);
        }
        let total_sections = header
            .ar1cs_byte_len
            .checked_add(header.vk_byte_len)
            .and_then(|s| s.checked_add(header.pk_byte_len))
            .ok_or(ArzkeyError::FileTooLarge)?;
        if total_sections > MAX_ARZKEY_BYTES {
            return Err(ArzkeyError::FileTooLarge);
        }

        // Section 1 — embedded `.ar1cs`.
        let ar1cs_start = cursor.position() as usize;
        let body_remaining = (body.len() - ar1cs_start) as u64;
        if header.ar1cs_byte_len > body_remaining {
            return Err(ArzkeyError::Ar1csLengthMismatch {
                header: header.ar1cs_byte_len,
                actual: body_remaining,
            });
        }
        let ar1cs_end = ar1cs_start + header.ar1cs_byte_len as usize;
        let arcs = ArcsFile::<E::ScalarField>::read(&mut &body[ar1cs_start..ar1cs_end])?;
        if arcs.body_blake3() != header.ar1cs_blake3 {
            return Err(ArzkeyError::Ar1csBlake3Mismatch);
        }

        // Section 2 — VK.
        let vk_remaining = (body.len() - ar1cs_end) as u64;
        if header.vk_byte_len > vk_remaining {
            return Err(ArzkeyError::VkLengthMismatch {
                header: header.vk_byte_len,
                actual: vk_remaining,
            });
        }
        let vk_end = ar1cs_end + header.vk_byte_len as usize;
        let vk_section = &body[ar1cs_end..vk_end];
        if blake3::hash(vk_section).as_bytes() != &header.vk_blake3 {
            return Err(ArzkeyError::VkBlake3Mismatch);
        }
        let mut vk_reader: &[u8] = vk_section;
        let vk = VerifyingKey::<E>::deserialize_compressed(&mut vk_reader)?;
        if !vk_reader.is_empty() {
            return Err(ArzkeyError::VkLengthMismatch {
                header: header.vk_byte_len,
                actual: header.vk_byte_len - vk_reader.len() as u64,
            });
        }

        // Section 3 — PK.
        let pk_remaining = (body.len() - vk_end) as u64;
        if header.pk_byte_len > pk_remaining {
            return Err(ArzkeyError::PkLengthMismatch {
                header: header.pk_byte_len,
                actual: pk_remaining,
            });
        }
        let pk_end = vk_end + header.pk_byte_len as usize;
        let pk_section = &body[vk_end..pk_end];
        let mut pk_reader: &[u8] = pk_section;
        let pk = ProvingKey::<E>::deserialize_compressed(&mut pk_reader)?;
        if !pk_reader.is_empty() {
            return Err(ArzkeyError::PkLengthMismatch {
                header: header.pk_byte_len,
                actual: header.pk_byte_len - pk_reader.len() as u64,
            });
        }

        // OV-2 — VK duplication consistency: pk.vk MUST equal the standalone
        // vk_section after both deserialize. Tampering one without the other
        // surfaces here as VkDuplicationDrift.
        if pk.vk != vk {
            return Err(ArzkeyError::VkDuplicationDrift);
        }

        if pk_end != body.len() {
            return Err(ArzkeyError::TrailingBytes((body.len() - pk_end) as u64));
        }

        let file = ArzkeyFile {
            header,
            arcs,
            vk,
            pk,
        };
        file.validate()?;
        Ok(file)
    }
}
