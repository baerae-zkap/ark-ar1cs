use std::io::{Read, Write};

use crate::error::ArcsError;

pub const MAGIC: &[u8; 6] = b"AR1CS\x00";
pub const VERSION_V0: u8 = 0x00;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveId {
    Bn254 = 0x01,
    Bls12_381 = 0x02,
    Bls12_377 = 0x03,
}

impl TryFrom<u8> for CurveId {
    type Error = ArcsError;
    fn try_from(v: u8) -> Result<Self, ArcsError> {
        match v {
            0x01 => Ok(CurveId::Bn254),
            0x02 => Ok(CurveId::Bls12_381),
            0x03 => Ok(CurveId::Bls12_377),
            other => Err(ArcsError::UnsupportedCurve(other)),
        }
    }
}

/// The fixed-size binary header for an `.ar1cs` file.
///
/// Layout (33 bytes total):
///   magic[6]  version[1]  curve_id[1]  reserved[1]
///   num_instance_variables[8 LE]
///   num_witness_variables[8 LE]
///   num_constraints[8 LE]
///   a_non_zero[8 LE]
///   b_non_zero[8 LE]
///   c_non_zero[8 LE]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcsHeader {
    pub version: u8,
    pub curve_id: CurveId,
    /// Total instance variables including the implicit "1" wire at index 0.
    pub num_instance_variables: u64,
    pub num_witness_variables: u64,
    pub num_constraints: u64,
    pub a_non_zero: u64,
    pub b_non_zero: u64,
    pub c_non_zero: u64,
}

impl ArcsHeader {
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArcsError> {
        w.write_all(MAGIC)?;
        w.write_all(&[self.version, self.curve_id as u8, 0x00])?;
        w.write_all(&self.num_instance_variables.to_le_bytes())?;
        w.write_all(&self.num_witness_variables.to_le_bytes())?;
        w.write_all(&self.num_constraints.to_le_bytes())?;
        w.write_all(&self.a_non_zero.to_le_bytes())?;
        w.write_all(&self.b_non_zero.to_le_bytes())?;
        w.write_all(&self.c_non_zero.to_le_bytes())?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArcsError> {
        let mut magic = [0u8; 6];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(ArcsError::InvalidMagic);
        }

        let mut meta = [0u8; 3];
        r.read_exact(&mut meta)?;
        let version = meta[0];
        if version != VERSION_V0 {
            return Err(ArcsError::UnsupportedVersion(version));
        }
        let curve_id = CurveId::try_from(meta[1])?;
        // meta[2] is reserved — ignored

        let mut buf = [0u8; 8];
        macro_rules! read_u64 {
            () => {{
                r.read_exact(&mut buf)?;
                u64::from_le_bytes(buf)
            }};
        }

        Ok(ArcsHeader {
            version,
            curve_id,
            num_instance_variables: read_u64!(),
            num_witness_variables: read_u64!(),
            num_constraints: read_u64!(),
            a_non_zero: read_u64!(),
            b_non_zero: read_u64!(),
            c_non_zero: read_u64!(),
        })
    }
}
