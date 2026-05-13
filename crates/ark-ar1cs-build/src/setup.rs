//! Build-time setup-output wrapper: bundle an `.ar1cs` envelope and a
//! Groth16 `ProvingKey` into the atomic [`ArzkeyFile`] artifact.
//!
//! Read-side concerns ([`ArzkeyFile::read`], [`ArzkeyFile::validate`]) stay
//! in `ark_ar1cs::arzkey`; this module hosts the *write-side* constructor
//! that derives the verifying key, computes section blake3 digests, and
//! fills in [`ark_ar1cs::arzkey::ArzkeyHeader`].

use ark_ec::pairing::Pairing;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalSerialize;

use ark_ar1cs::arzkey::{ArzkeyFile, ArzkeyHeader, ARZKEY_VERSION_CURRENT};
use ark_ar1cs::format::ArcsFile;

/// Atomic constructor — `vk` is derived from `pk.vk.clone()` so PK/VK
/// drift inside a single `.arzkey` is structurally impossible (ARCH-3).
/// Caller cannot supply a `vk` that disagrees with `pk.vk`.
pub fn from_setup_output<E: Pairing>(
    arcs: ArcsFile<E::ScalarField>,
    pk: ProvingKey<E>,
) -> ArzkeyFile<E> {
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
    let vk_byte_len = vk.uncompressed_size() as u64;
    let mut vk_bytes = Vec::with_capacity(vk_byte_len as usize);
    vk.serialize_uncompressed(&mut vk_bytes)
        .expect("VerifyingKey serialize to Vec cannot fail");
    let vk_blake3 = *blake3::hash(&vk_bytes).as_bytes();

    let pk_byte_len = pk.uncompressed_size() as u64;

    let header = ArzkeyHeader {
        version: ARZKEY_VERSION_CURRENT,
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
