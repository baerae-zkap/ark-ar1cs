use std::io::{Read, Write};

use ark_ar1cs_format::CurveId;

use crate::error::ArwtnsError;

pub const ARWTNS_MAGIC: &[u8; 6] = b"ARWTNS";
pub const ARWTNS_VERSION_V0: u8 = 0x00;

/// Fixed `.arwtns` header size in bytes.
///
/// Layout (64 bytes total):
///
/// ```text
///   magic[6] version[1] curve_id[1] reserved[8]
///   ar1cs_blake3[32] num_instance[8 LE] num_witness[8 LE]
/// ```
pub const ARWTNS_HEADER_SIZE: usize = 64;

/// The fixed-size binary header for an `.arwtns` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArwtnsHeader {
    pub version: u8,
    pub curve_id: CurveId,
    /// Blake3 of the canonical `.ar1cs` body that this witness satisfies.
    /// Sourced from `ArcsFile::body_blake3()`; binds CIRCUIT identity (not
    /// ceremony identity — see vision §1).
    pub ar1cs_blake3: [u8; 32],
    /// Number of public-input field elements in the body. Excludes the
    /// implicit `1` wire at variable index 0.
    pub num_instance: u64,
    /// Number of witness field elements in the body.
    pub num_witness: u64,
}

impl ArwtnsHeader {
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArwtnsError> {
        w.write_all(ARWTNS_MAGIC)?;
        w.write_all(&[self.version, self.curve_id as u8])?;
        w.write_all(&[0u8; 8])?;
        w.write_all(&self.ar1cs_blake3)?;
        w.write_all(&self.num_instance.to_le_bytes())?;
        w.write_all(&self.num_witness.to_le_bytes())?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, ArwtnsError> {
        let mut magic = [0u8; 6];
        r.read_exact(&mut magic)?;
        if &magic != ARWTNS_MAGIC {
            return Err(ArwtnsError::BadMagic);
        }

        let mut vc = [0u8; 2];
        r.read_exact(&mut vc)?;
        let version = vc[0];
        if version != ARWTNS_VERSION_V0 {
            return Err(ArwtnsError::UnsupportedVersion(version));
        }
        let curve_id = CurveId::try_from(vc[1])?;

        let mut reserved = [0u8; 8];
        r.read_exact(&mut reserved)?;
        if reserved != [0u8; 8] {
            return Err(ArwtnsError::ReservedNotZero);
        }

        let mut ar1cs_blake3 = [0u8; 32];
        r.read_exact(&mut ar1cs_blake3)?;

        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        let num_instance = u64::from_le_bytes(buf);
        r.read_exact(&mut buf)?;
        let num_witness = u64::from_le_bytes(buf);

        Ok(ArwtnsHeader {
            version,
            curve_id,
            ar1cs_blake3,
            num_instance,
            num_witness,
        })
    }
}
