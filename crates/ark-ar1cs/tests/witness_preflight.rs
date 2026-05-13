#![allow(clippy::unwrap_used, clippy::expect_used)]

//! B3 — integration test wiring [`synthesize_full_assignment`] into the new
//! `prove(&pk, &arcs, &full, &mut rng)` API.
//!
//! Steps:
//! 1. Build a concrete fully-assigned `MulCircuit` (`x * y = z`, z public,
//!    x and y witness).
//! 2. Export the constraint system to `.ar1cs` bytes via
//!    `ark_ar1cs_build::export_circuit`, then re-import as an
//!    `ImportedCircuit` and run Groth16 setup against the imported view.
//!    This is the same export → setup path real consumers cross.
//! 3. Parse the `.ar1cs` bytes back into an `ArcsFile<Fr>`.
//! 4. Call [`synthesize_full_assignment`] on a freshly-built `MulCircuit`
//!    with concrete values; assert the layout/length invariants.
//! 5. Call `prove(&pk, &arcs, &full, &mut rng)` and assert `Ok(Proof)`.
//! 6. Verify the proof directly via `ark_groth16::Groth16::verify_proof`
//!    (the `verify` wrapper is removed in Commit 5; this commit keeps it
//!    around for transitional callers, but B3 demonstrates the
//!    caller-direct pattern that survives that removal).

#![cfg(not(target_arch = "wasm32"))]

use ark_ar1cs::format::importer::ImportedCircuit;
use ark_ar1cs::format::{ArcsFile, CurveId};
use ark_ar1cs::{prove, synthesize_full_assignment};
use ark_ar1cs_build::export_circuit;
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_std::rand::{rngs::StdRng, SeedableRng};

/// `x * y = z`, with `z` public and `x`, `y` witness. Wire layout (matches
/// arkworks's allocation order):
///   index 0 — implicit "1" wire
///   index 1 — z (instance)
///   index 2 — x (witness)
///   index 3 — y (witness)
#[derive(Clone, Copy)]
struct MulCircuit {
    x: Fr,
    y: Fr,
    z: Fr,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let z = cs.new_input_variable(|| Ok(self.z))?;
        let x = cs.new_witness_variable(|| Ok(self.x))?;
        let y = cs.new_witness_variable(|| Ok(self.y))?;
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(x),
            || LinearCombination::from(y),
            || LinearCombination::from(z),
        )?;
        Ok(())
    }
}

#[test]
fn synthesize_full_assignment_feeds_prove_bn254() {
    let circuit = MulCircuit {
        x: Fr::from(6u64),
        y: Fr::from(7u64),
        z: Fr::from(42u64),
    };
    let mut rng = StdRng::from_seed([11u8; 32]);

    // Export the circuit to .ar1cs bytes and re-import for Groth16 setup —
    // the production setup path. Parses the same bytes back into an
    // ArcsFile<Fr> for prove.
    let mut arcs_bytes = Vec::new();
    export_circuit::<Fr, _, _>(circuit, CurveId::Bn254, &mut arcs_bytes)
        .expect("export_circuit should not fail");

    let imported = ImportedCircuit::<Fr>::from_reader(&mut arcs_bytes.as_slice(), CurveId::Bn254)
        .expect("ImportedCircuit::from_reader should not fail");
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(imported, &mut rng)
        .expect("Groth16 setup should not fail");

    let arcs = ArcsFile::<Fr>::read(&mut arcs_bytes.as_slice())
        .expect("ArcsFile::read on freshly-written bytes should not fail");

    // Synthesize the full assignment from a fresh circuit instance with
    // the same concrete values.
    let full = synthesize_full_assignment::<_, Fr>(circuit)
        .expect("synthesize_full_assignment should not fail on a fully-assigned circuit");

    // Layout / length invariants (B1, B2 — also covered by witness.rs unit
    // tests; re-asserted here in the integration context).
    assert_eq!(
        full.len(),
        (arcs.header.num_instance_variables + arcs.header.num_witness_variables) as usize,
        "B2: full.len() must equal num_instance + num_witness"
    );
    assert_eq!(full[0], Fr::ONE, "B1: index 0 must be F::ONE");
    assert_eq!(full[1], Fr::from(42u64), "B1: index 1 must be z (instance)");
    assert_eq!(full[2], Fr::from(6u64), "B1: index 2 must be x (witness)");
    assert_eq!(full[3], Fr::from(7u64), "B1: index 3 must be y (witness)");

    // B3 — the helper's output is accepted by prove and produces a proof
    // that verifies against pk.vk.
    let proof = prove(&pk, &arcs, &full, &mut rng).expect("prove should not fail");

    let pvk = prepare_verifying_key(&pk.vk);
    let public_inputs = &full[1..arcs.header.num_instance_variables as usize];
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, public_inputs)
        .expect("Groth16::verify_proof should not error");
    assert!(
        ok,
        "B3: synthesize_full_assignment + prove must produce a verifying proof"
    );
}
