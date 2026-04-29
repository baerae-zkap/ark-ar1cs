use std::io::{Read, Write};

use ark_ar1cs_format::CurveId;

use crate::error::ArzkeyError;

pub const ARZKEY_MAGIC: &[u8; 6] = b"ARZKEY";
pub const ARZKEY_VERSION_V0: u8 = 0x00;

/// Fixed `.arzkey` header size in bytes.
///
/// Byte layout (128 bytes total):
///
/// ```text
///   magic[6]                                    "ARZKEY"
///   version[1]
///   curve_id[1]
///   reserved[8]                                 (MUST be zero on read)
///   ar1cs_blake3[32]                            blake3 of canonical .ar1cs body
///   vk_blake3[32]                               blake3 of standalone vk_section (OV-3)
///   ar1cs_byte_len[8 LE]                        length of embedded .ar1cs (ARCH-2)
///   vk_byte_len[8 LE]
///   pk_byte_len[8 LE]
///   num_instance_variables[8 LE]                mirror of arcs.header
///   num_witness_variables[8 LE]
///   num_constraints[8 LE]
/// ```
pub const ARZKEY_HEADER_SIZE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArzkeyHeader {
    pub version: u8,
    pub curve_id: CurveId,
    pub ar1cs_blake3: [u8; 32],
    pub vk_blake3: [u8; 32],
    pub ar1cs_byte_len: u64,
    pub vk_byte_len: u64,
    pub pk_byte_len: u64,
    pub num_instance_variables: u64,
    pub num_witness_variables: u64,
    pub num_constraints: u64,
}

impl ArzkeyHeader {
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArzkeyError> {
        w.write_all(ARZKEY_MAGIC)?;
        w.write_all(&[self.version, self.curve_id as u8])?;
        w.write_all(&[0u8; 8])?;
        w.write_all(&self.ar1cs_blake3)?;
        w.write_all(&self.vk_blake3)?;
        w.write_all(&self.ar1cs_byte_len.to_le_bytes())?;
        w.write_all(&self.vk_byte_len.to_le_bytes())?;
        w.write_all(&self.pk_byte_len.to_le_bytes())?;
        w.write_all(&self.num_instance_variables.to_le_bytes())?;
        w.write_all(&self.num_witness_variables.to_le_bytes())?;
        w.write_all(&self.num_constraints.to_le_bytes())?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArzkeyError> {
        let mut magic = [0u8; 6];
        r.read_exact(&mut magic)?;
        if &magic != ARZKEY_MAGIC {
            return Err(ArzkeyError::BadMagic);
        }

        let mut vc = [0u8; 2];
        r.read_exact(&mut vc)?;
        let version = vc[0];
        if version != ARZKEY_VERSION_V0 {
            return Err(ArzkeyError::UnsupportedVersion(version));
        }
        let curve_id = CurveId::try_from(vc[1])?;

        let mut reserved = [0u8; 8];
        r.read_exact(&mut reserved)?;
        if reserved != [0u8; 8] {
            return Err(ArzkeyError::ReservedNotZero);
        }

        let mut ar1cs_blake3 = [0u8; 32];
        r.read_exact(&mut ar1cs_blake3)?;
        let mut vk_blake3 = [0u8; 32];
        r.read_exact(&mut vk_blake3)?;

        let mut buf = [0u8; 8];
        macro_rules! read_u64 {
            () => {{
                r.read_exact(&mut buf)?;
                u64::from_le_bytes(buf)
            }};
        }

        let ar1cs_byte_len = read_u64!();
        let vk_byte_len = read_u64!();
        let pk_byte_len = read_u64!();
        let num_instance_variables = read_u64!();
        let num_witness_variables = read_u64!();
        let num_constraints = read_u64!();

        Ok(ArzkeyHeader {
            version,
            curve_id,
            ar1cs_blake3,
            vk_blake3,
            ar1cs_byte_len,
            vk_byte_len,
            pk_byte_len,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        })
    }
}
