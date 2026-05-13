//! End-to-end zkap-zkp integration pattern over BN254.
//!
//! This is the example that captures the project's identity-success
//! milestone: the entire ark-ar1cs surface composes into a single
//! `prove → verify == true` flow with no original `ConstraintSynthesizer`
//! at prove time.
//!
//! Pipeline (all five steps run in this single binary; in production
//! they run on different machines and consume `.ar1cs` / `.arzkey` byte
//! artifacts handed off across component boundaries):
//!
//! 1. **Export** — synthesize a `ConstraintSynthesizer` and write
//!    `.ar1cs` bytes via `ark_ar1cs_build::export_circuit`.
//! 2. **Setup** — re-import the bytes as an `ImportedCircuit`
//!    (no original Rust circuit needed) and run
//!    `Groth16::generate_random_parameters_with_reduction` to produce
//!    a `ProvingKey<Bn254>`.
//! 3. **Wrap setup output** — bundle the matrices and the proving key
//!    as a single `.arzkey` via
//!    `ark_ar1cs_build::from_setup_output(arcs, pk)`. The verifying key is
//!    derived internally from `pk.vk.clone()` so PK/VK drift is
//!    structurally impossible.
//! 4. **Build full assignment** — compute the witness `(x, y = x*x)`
//!    for a concrete instance and assemble the prover-shaped
//!    `[Fr::ONE, y, x]` vector directly. ark-ar1cs no longer requires
//!    the caller to pass through a `.arwtns` envelope — `prove`
//!    consumes a raw slice.
//! 5. **Prove and verify** — `prove(&arzkey, &full_assignment, &mut rng)`
//!    runs the R1CS pre-flight + Groth16 proof construction;
//!    `verify(&arzkey, &public_inputs, &proof)` checks the pairing.
//!
//! ## Optional header binding (caller's one-line responsibility)
//!
//! ark-ar1cs no longer wires a `bind_check` automatically. Production
//! callers who want to make sure the loaded `.arzkey` matches an
//! out-of-band expected circuit identity (e.g. from a deployment
//! manifest) perform the comparison themselves before calling `prove`:
//!
//! ```ignore
//! use ark_ar1cs::{ArtifactMismatchReason, ProverError};
//!
//! if arzkey.header.ar1cs_blake3 != expected_ar1cs_blake3 {
//!     return Err(ProverError::ArtifactMismatch {
//!         reason: ArtifactMismatchReason::Ar1csBlake3,
//!     });
//! }
//! prove(&arzkey, &full_assignment, &mut rng)?;
//! ```

use std::error::Error;

use ark_ar1cs::format::importer::ImportedCircuit;
use ark_ar1cs::format::{ArcsFile, CurveId};
use ark_ar1cs::{prove, verify};
use ark_ar1cs_build::{export_circuit, from_setup_output};
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_relations::gr1cs::{
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
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(x_var),
            || LinearCombination::from(x_var),
            || LinearCombination::from(y_var),
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
    let arzkey = from_setup_output::<Bn254>(arcs, pk);
    println!(
        "[3/5] arzkey wrapped  → ar1cs_byte_len={}, vk_byte_len={}, pk_byte_len={}",
        arzkey.header.ar1cs_byte_len, arzkey.header.vk_byte_len, arzkey.header.pk_byte_len,
    );

    // 4. Witness producer side — compute (x, y = x*x) and build the full
    //    assignment vector [Fr::ONE, y, x] that prove() consumes.
    //    Production callers can additionally compare
    //    `arzkey.header.ar1cs_blake3` against an expected circuit
    //    identity here (see the module-level doc-comment for the
    //    one-line pattern).
    let x = Fr::from(3u64);
    let y = x * x;
    let full_assignment: Vec<Fr> = vec![Fr::ONE, y, x];
    println!(
        "[4/5] full assignment → [Fr::ONE, y, x] (len={})",
        full_assignment.len()
    );

    // 5. prove() runs the length check, the R1CS pre-flight, and the
    //    Groth16 proof construction. verify() checks the pairing
    //    against arzkey.vk(); Ok(true) means the public input + proof
    //    are consistent with the embedded VK.
    let proof = prove(&arzkey, &full_assignment, &mut rng)?;
    let public_inputs = [y];
    let ok = verify(&arzkey, &public_inputs, &proof)?;
    println!("[5/5] verify          → {ok}");

    assert!(ok, "valid witness must produce a verifying proof");
    Ok(())
}
