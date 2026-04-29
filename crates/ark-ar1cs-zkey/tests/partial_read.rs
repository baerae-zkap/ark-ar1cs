//! Phase D.6 / TEST-5 / OV-3 — header-only partial-read VK extraction.
//!
//! Validates the partial-read claim from the design doc: a verifier-only
//! consumer can fetch the outer 128-byte `ArzkeyHeader`, skip past the
//! embedded `.ar1cs` body using the header-declared `ar1cs_byte_len`, slice
//! exactly `vk_byte_len` bytes from the disk file, authenticate that slice
//! against `header.vk_blake3` (OV-3), and deserialize the `VerifyingKey` —
//! *without ever reading the embedded `.ar1cs` body*.
//!
//! # TEST-5 hard requirement (structural enforcement)
//!
//! This file MUST NOT call `ArcsFile::read`. The invariant is enforced
//! structurally — the partial-read helper jumps directly from the header
//! end to `vk_offset` via `Seek::seek` and reads exactly `vk_byte_len`
//! bytes from there. PR review should grep this file for `ArcsFile::read`
//! and refuse merges that introduce it.
//!
//! # Per `partial-read-needs-section-auth` (9/10)
//!
//! The Blake3 trailer covers the whole file, so a partial reader can't
//! verify it. `header.vk_blake3` (OV-3 add-on) authenticates the VK
//! section in isolation — the test asserts authentication runs *before*
//! `VerifyingKey::deserialize_compressed`.
//!
//! # Per `ar1cs-blake3-binds-circuit-not-ceremony` (9/10)
//!
//! Production consumers that need to detect a *ceremony swap* must
//! additionally pin the `.arzkey` hash itself out-of-band. This test
//! validates the format-level partial-read algorithm only; deployment
//! pipelines bear the wider responsibility.
//!
//! # 100 MB scale target
//!
//! The headline 100 MB acceptance from the design doc is about
//! seek-extraction *latency*, not algorithm correctness. The
//! `#[ignore]`-gated test scales the embedded constraint system up to a
//! few-MiB file as a structural sanity check; reaching 100 MB would
//! require ~5·10^5 chained constraints with several minutes of Groth16
//! setup time, deferred to a manual benchmark run.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_zkey::{ArzkeyFile, ArzkeyHeader, ARZKEY_HEADER_SIZE};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, VerifyingKey};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    OptimizationGoal, SynthesisError, SynthesisMode, Variable,
};
use ark_serialize::CanonicalDeserialize;
use tempfile::NamedTempFile;

#[derive(Clone)]
struct SquareCircuit {
    x: Option<Fr>,
    y: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y_var = cs.new_input_variable(|| Ok(self.y))?;
        cs.enforce_constraint(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var),
            LinearCombination::from(y_var),
        )?;
        Ok(())
    }
}

#[derive(Clone)]
struct ChainedSquares {
    initial: Option<Fr>,
    num_iter: usize,
    final_y: Fr,
}

impl ConstraintSynthesizer<Fr> for ChainedSquares {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let final_var = cs.new_input_variable(|| Ok(self.final_y))?;
        let mut current = cs
            .new_witness_variable(|| self.initial.ok_or(SynthesisError::AssignmentMissing))?;
        for i in 0..self.num_iter {
            let next: Variable = if i + 1 == self.num_iter {
                final_var
            } else {
                cs.new_witness_variable(|| Ok(Fr::from(0u64)))?
            };
            cs.enforce_constraint(
                LinearCombination::from(current),
                LinearCombination::from(current),
                LinearCombination::from(next),
            )?;
            current = next;
        }
        Ok(())
    }
}

fn build_arzkey<C: ConstraintSynthesizer<Fr> + Clone>(circuit: C) -> ArzkeyFile<Bn254> {
    let mut rng = ark_std::test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
        .expect("Groth16 setup should not fail");

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .expect("synthesize for matrices should not fail");
    cs.finalize();
    let matrices = cs.to_matrices().expect("to_matrices() should not fail");
    let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);
    ArzkeyFile::<Bn254>::from_setup_output(arcs, pk)
}

/// Header-only partial-read of the VK section.
///
/// Sequence (TEST-5 / OV-3):
/// 1. Read first `ARZKEY_HEADER_SIZE` (128) bytes only — outer header.
/// 2. `seek(SeekFrom::Start(HEADER_SIZE + ar1cs_byte_len))` — skip the
///    embedded `.ar1cs` body without reading it (structural enforcement
///    of the TEST-5 "no ArcsFile::read" invariant).
/// 3. Read exactly `vk_byte_len` bytes.
/// 4. `blake3(slice) == header.vk_blake3` — OV-3 partial-read auth, runs
///    *before* the deserialize so unauthenticated bytes never touch
///    `VerifyingKey::deserialize_compressed`.
/// 5. Deserialize.
fn partial_read_vk_from_disk(path: &Path) -> VerifyingKey<Bn254> {
    let mut file = File::open(path).expect("open tempfile");

    let mut header_buf = [0u8; ARZKEY_HEADER_SIZE];
    file.read_exact(&mut header_buf)
        .expect("file must contain HEADER_SIZE bytes");
    let header = ArzkeyHeader::read(&mut &header_buf[..])
        .expect("ArzkeyHeader::read on a freshly-written .arzkey must succeed");

    let vk_offset = ARZKEY_HEADER_SIZE as u64 + header.ar1cs_byte_len;
    file.seek(SeekFrom::Start(vk_offset))
        .expect("seek to vk_offset");

    let mut vk_section = vec![0u8; header.vk_byte_len as usize];
    file.read_exact(&mut vk_section)
        .expect("file must contain vk_byte_len bytes at vk_offset");

    let computed = *blake3::hash(&vk_section).as_bytes();
    assert_eq!(
        computed, header.vk_blake3,
        "OV-3: vk_blake3 must authenticate the VK section before deserialize"
    );

    VerifyingKey::<Bn254>::deserialize_compressed(&mut &vk_section[..])
        .expect("VerifyingKey::deserialize_compressed on authenticated bytes")
}

fn write_arzkey_to_tempfile(arzkey: &ArzkeyFile<Bn254>) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("NamedTempFile::new");
    arzkey
        .write(tmp.as_file_mut())
        .expect("ArzkeyFile::write to tempfile");
    tmp.as_file_mut().flush().expect("flush tempfile");
    tmp
}

#[test]
fn partial_read_extracts_authenticated_vk() {
    let arzkey = build_arzkey(SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    });

    let tmp = write_arzkey_to_tempfile(&arzkey);

    let extracted_vk = partial_read_vk_from_disk(tmp.path());
    assert_eq!(
        &extracted_vk,
        arzkey.vk(),
        "header-only partial-read VK MUST equal full-read arzkey.vk()"
    );
}

#[test]
fn partial_read_does_not_reach_pk_or_trailer() {
    // Structural sanity: the bytes beyond `HEADER_SIZE + ar1cs_byte_len +
    // vk_byte_len` are the PK section + 32-byte Blake3 trailer. The
    // partial-read helper only reads through `vk_offset + vk_byte_len`;
    // the rest of the file could be tampered with and the partial-read
    // would still succeed (because OV-3 only authenticates the VK
    // section, not the whole file). This invariant is what makes HTTP
    // Range requests for VK extraction useful — verifying that
    // `partial_read_vk_from_disk` honors it.
    let arzkey = build_arzkey(SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    });

    let tmp = write_arzkey_to_tempfile(&arzkey);

    // Tamper the PK / trailer region (everything past the VK section)
    // with random bytes. ArcsFile::read or ArzkeyFile::read would now
    // reject this file (trailer mismatch), but partial_read should still
    // recover the VK because it never touches that region.
    let pk_start =
        ARZKEY_HEADER_SIZE as u64 + arzkey.header.ar1cs_byte_len + arzkey.header.vk_byte_len;
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path())
            .expect("reopen for tamper");
        file.seek(SeekFrom::Start(pk_start))
            .expect("seek to pk_start");
        let garbage = vec![0xAAu8; 32];
        file.write_all(&garbage).expect("tamper write");
        file.flush().expect("flush after tamper");
    }

    let extracted_vk = partial_read_vk_from_disk(tmp.path());
    assert_eq!(
        &extracted_vk,
        arzkey.vk(),
        "partial-read MUST NOT depend on bytes past vk_offset+vk_byte_len"
    );
}

#[test]
#[ignore = "scale test (D.6 / TEST-5 latency target). Run with `cargo test --release -- --ignored`"]
fn partial_read_scales_to_a_realistic_arzkey() {
    // ChainedSquares with N = 4096 produces a multi-MiB .arzkey
    // (Groth16 PK dominates). The headline 100 MB target in the design
    // doc would require N ≈ 5·10^5 with several minutes of Groth16
    // setup — deferred to a manual benchmark run. This #[ignore] gate
    // keeps regular CI fast while still exercising the partial-read
    // code path on a non-trivial file.
    let arzkey = build_arzkey(ChainedSquares {
        initial: None,
        num_iter: 4096,
        final_y: Fr::from(0u64),
    });

    let tmp = write_arzkey_to_tempfile(&arzkey);

    let on_disk = std::fs::metadata(tmp.path())
        .expect("stat tempfile")
        .len();
    eprintln!(
        "partial_read_scales_to_a_realistic_arzkey: file size = {on_disk} bytes \
         (ar1cs = {ar1cs}, vk = {vk}, pk = {pk})",
        ar1cs = arzkey.header.ar1cs_byte_len,
        vk = arzkey.header.vk_byte_len,
        pk = arzkey.header.pk_byte_len,
    );

    let extracted_vk = partial_read_vk_from_disk(tmp.path());
    assert_eq!(&extracted_vk, arzkey.vk());
}
