//! End-to-end zkap-zkp integration pattern over BN254.
//!
//! This is the example that captures the project's identity-success
//! milestone: the entire ark-ar1cs surface composes into a single
//! `prove → verify == true` flow with no original `ConstraintSynthesizer`
//! at prove time.
//!
//! Pipeline (all five steps run in this single binary; in production
//! they run on different machines and consume `.ar1cs` / `.arzkey` /
//! `.arwtns` byte artifacts handed off across component boundaries):
//!
//! 1. **Export** — synthesize a `ConstraintSynthesizer` and write
//!    `.ar1cs` bytes via `ark_ar1cs_format::exporter::export_circuit`.
//! 2. **Setup** — re-import the bytes as an `ImportedCircuit`
//!    (no original Rust circuit needed) and run
//!    `Groth16::generate_random_parameters_with_reduction` to produce
//!    a `ProvingKey<Bn254>`.
//! 3. **Wrap setup output** — bundle the matrices and the proving key
//!    as a single `.arzkey` via
//!    `ArzkeyFile::from_setup_output(arcs, pk)`. The verifying key is
//!    derived internally from `pk.vk.clone()` so PK/VK drift is
//!    structurally impossible.
//! 4. **Wrap witness** — compute the assignment `(x, y = x*x)` for a
//!    concrete instance and wrap it as `.arwtns` via
//!    `ArwtnsFile::from_assignments`. The body excludes the implicit
//!    "1" wire — the prover prepends it.
//! 5. **Prove and verify** — `prove(&arzkey, &arwtns, &mut rng)` runs
//!    bind_check + R1CS pre-flight + Groth16 proof construction;
//!    `verify(&arzkey, &public_inputs, &proof)` checks the pairing.

use std::error::Error;

use ark_ar1cs_format::exporter::export_circuit;
use ark_ar1cs_format::importer::ImportedCircuit;
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_prover::{prove, verify};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use rand::{rngs::StdRng, SeedableRng};

/// `x * x = y` with `y` public and `x` private.
///
/// Variable layout (matches arkworks):
///   index 0 — implicit "1" wire
///   index 1 — y (public input)
///   index 2 — x (witness)
#[derive(Clone)]
struct SquareCircuit {
    x: Option<Fr>,
    y: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let y_var = cs.new_input_variable(|| Ok(self.y))?;
        let x_var =
            cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var),
            LinearCombination::from(y_var),
        )?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = StdRng::from_seed([7u8; 32]);

    // 1. Export the circuit to .ar1cs bytes. This is the byte that the
    //    setup machine and the witness producer both reference; in
    //    production it would be uploaded to a known location.
    let setup_circuit = SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    };
    let mut arcs_bytes = Vec::new();
    export_circuit::<Fr, _, _>(setup_circuit, CurveId::Bn254, &mut arcs_bytes)?;
    println!("[1/5] export_circuit  → {:>6} bytes", arcs_bytes.len());

    // 2. Re-import and run trusted setup. ImportedCircuit reads the
    //    .ar1cs bytes and surfaces them as a ConstraintSynthesizer; no
    //    original Rust circuit is required at this point.
    let imported = ImportedCircuit::<Fr>::from_reader(&mut &arcs_bytes[..], CurveId::Bn254)?;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(imported, &mut rng)?;
    println!("[2/5] groth16 setup   → ProvingKey<Bn254>");

    // 3. Wrap (matrices, pk) as one .arzkey. Consumers ship this file as
    //    the atomic ceremony output; the embedded VK is derived from
    //    pk.vk.clone() so PK/VK drift is structurally impossible.
    let arcs = ArcsFile::<Fr>::read(&mut &arcs_bytes[..])?;
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);
    println!(
        "[3/5] arzkey wrapped  → ar1cs_byte_len={}, vk_byte_len={}, pk_byte_len={}",
        arzkey.header.ar1cs_byte_len, arzkey.header.vk_byte_len, arzkey.header.pk_byte_len,
    );

    // 4. Witness producer side — compute (x, y = x*x) and emit .arwtns.
    //    The instance slice excludes the implicit "1" wire; the prover
    //    prepends F::ONE inside full_assignment_with_one_wire().
    let x = Fr::from(3u64);
    let y = x * x;
    let arwtns = ArwtnsFile::<Fr>::from_assignments(
        CurveId::Bn254,
        arzkey.header.ar1cs_blake3,
        &[y], // public input
        &[x], // private witness
    );
    println!("[4/5] arwtns wrapped  → instance=[y], witness=[x]");

    // 5. prove() runs the four bind rules, the R1CS pre-flight, and
    //    Groth16 proof construction. verify() checks the pairing
    //    against arzkey.vk(); Ok(true) means the public input + proof
    //    are consistent with the embedded VK.
    let proof = prove(&arzkey, &arwtns, &mut rng)?;
    let public_inputs = [y];
    let ok = verify(&arzkey, &public_inputs, &proof)?;
    println!("[5/5] verify          → {ok}");

    assert!(ok, "valid witness must produce a verifying proof");
    Ok(())
}
