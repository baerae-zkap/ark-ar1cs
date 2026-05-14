//! End-to-end zkap-zkp integration pattern over BN254.
//!
//! This is the example that captures the project's identity-success
//! milestone: the entire ark-ar1cs surface composes into a single
//! `prove → verify == true` flow with no original `ConstraintSynthesizer`
//! at prove time.
//!
//! Pipeline (all four steps run in this single binary; in production
//! they run on different machines and consume `.ar1cs` bytes + a
//! separately-distributed `ProvingKey<E>` handed off across component
//! boundaries):
//!
//! 1. **Export** — synthesize a `ConstraintSynthesizer` and write
//!    `.ar1cs` bytes via `ark_ar1cs_build::export_circuit`.
//! 2. **Setup** — re-import the bytes as an `ImportedCircuit`
//!    (no original Rust circuit needed) and run
//!    `Groth16::generate_random_parameters_with_reduction` to produce
//!    a `ProvingKey<Bn254>`. Distribute the proving key out of band
//!    (`pk.serialize_uncompressed`) — there is no envelope helper.
//! 3. **Build full assignment** — compute the witness `(x, y = x*x)`
//!    for a concrete instance and assemble the prover-shaped
//!    `[Fr::ONE, y, x]` vector directly.
//! 4. **Prove and verify** —
//!    `prove(&pk, &arcs, &full_assignment, &mut rng)` runs the R1CS
//!    pre-flight + Groth16 proof construction;
//!    `Groth16::verify_proof(&prepare_verifying_key(&pk.vk), &proof,
//!    &public_inputs)` checks the pairing.
//!
//! ## Optional header binding (caller's one-line responsibility)
//!
//! `prove` does not bind circuit identity inside the call. Production
//! callers who want to make sure the loaded artifacts match an
//! out-of-band expected circuit identity (e.g. from a deployment
//! manifest) perform the comparison themselves before calling `prove`:
//!
//! ```ignore
//! if arcs.body_blake3() != manifest.expected_ar1cs_blake3 {
//!     return Err(MyCallerError::WrongCircuitArtifact);
//! }
//! prove(&pk, &arcs, &full_assignment, &mut rng)?;
//! ```
//!
//! See `docs/artifact-trust-boundary.md` for the rationale.

use std::error::Error;

use ark_ar1cs::format::importer::ImportedCircuit;
use ark_ar1cs::format::{ArcsFile, CurveId};
use ark_ar1cs::prove;
use ark_ar1cs_build::export_circuit;
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Groth16};
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

    // 1. Export the circuit to .ar1cs bytes. In production these bytes
    //    are the artifact shipped to the prove-time host.
    let setup_circuit = SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    };
    let mut arcs_bytes = Vec::new();
    export_circuit::<Fr, _, _>(setup_circuit, CurveId::Bn254, &mut arcs_bytes)?;
    println!("[1/4] export_circuit  → {:>6} bytes", arcs_bytes.len());

    // 2. Re-import and run trusted setup. ImportedCircuit reads the
    //    .ar1cs bytes and surfaces them as a ConstraintSynthesizer; no
    //    original Rust circuit is required at this point.
    let imported = ImportedCircuit::<Fr>::from_reader(&mut &arcs_bytes[..], CurveId::Bn254)?;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(imported, &mut rng)?;
    println!("[2/4] groth16 setup   → ProvingKey<Bn254>");

    // Parse the .ar1cs bytes back into an ArcsFile<Fr> for prove. The
    // proving key is held separately — there is no envelope.
    let arcs = ArcsFile::<Fr>::read(&mut &arcs_bytes[..])?;

    // 3. Witness producer side — compute (x, y = x*x) and build the full
    //    assignment vector [Fr::ONE, y, x] that prove() consumes.
    //    Production callers can additionally compare
    //    `arcs.body_blake3()` against an expected circuit identity
    //    here (see the module-level doc-comment for the one-line
    //    pattern).
    let x = Fr::from(3u64);
    let y = x * x;
    let full_assignment: Vec<Fr> = vec![Fr::ONE, y, x];
    println!(
        "[3/4] full assignment → [Fr::ONE, y, x] (len={})",
        full_assignment.len()
    );

    // 4. prove() runs the length check, the R1CS pre-flight, and the
    //    Groth16 proof construction. Verification is one line of
    //    arkworks — Ok(true) means the public input + proof are
    //    consistent with pk.vk.
    let proof = prove(&pk, &arcs, &full_assignment, &mut rng)?;
    let pvk = prepare_verifying_key(&pk.vk);
    let public_inputs = [y];
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)?;
    println!("[4/4] verify          → {ok}");

    assert!(ok, "valid witness must produce a verifying proof");
    Ok(())
}
