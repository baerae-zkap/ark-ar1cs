//! The same circuit, two pairing curves.
//!
//! BN254 is the workhorse curve covered by every fixture and property
//! test in the workspace. BLS12-381 is the cross-curve coverage that
//! ark-ar1cs ships at v0 to validate that the envelopes, hashes, and
//! prover are correct against a second `E: Pairing` and not merely
//! against BN254 happy paths. This example runs the
//! `synthesize → setup → prove → verify` pipeline on each curve and
//! prints both outcomes.
//!
//! The same `SquareCircuit<F>` body drives both runs; only the scalar
//! field, the `CurveId`, and the pairing engine vary. The mirror of
//! this example as an integration test lives at
//! `crates/ark-ar1cs-prover/tests/cross_curve.rs`.
//!
//! ## Optional header binding (caller's one-line responsibility)
//!
//! ark-ar1cs no longer wires a `bind_check` automatically. If a caller
//! wants to confirm the loaded `.arzkey` matches an expected circuit
//! identity, the comparison is one line before `prove`:
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
//!
//! (Wrong-curve `.arzkey` files are rejected one layer earlier by
//! `ArzkeyFile::<E>::read` at parse time — see the integration test
//! `tests/cross_curve.rs::wrong_curve_arzkey_rejected_at_parse_time`.)

use std::error::Error;

use ark_ar1cs::arzkey::ArzkeyFile;
use ark_ar1cs::format::{ArcsFile, CurveId};
use ark_ar1cs::{prove, verify};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    OptimizationGoal, SynthesisError, SynthesisMode,
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone)]
struct SquareCircuit<F: PrimeField> {
    x: Option<F>,
    y: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SquareCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
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

fn collect_matrices<F: PrimeField, C: ConstraintSynthesizer<F>>(
    circuit: C,
) -> Result<ark_ar1cs::format::ConstraintMatrices<F>, Box<dyn Error>> {
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    ark_ar1cs::format::ConstraintMatrices::from_cs(&cs)
        .map_err(|e| format!("ConstraintMatrices::from_cs failed: {e:?}").into())
}

/// Run the full pipeline on a single pairing curve `E`.
fn run_curve<E: Pairing>(curve_id: CurveId, x_value: u64) -> Result<bool, Box<dyn Error>> {
    let mut rng = StdRng::from_seed([curve_id as u8; 32]);

    let x = E::ScalarField::from(x_value);
    let y = x * x;

    // Setup against a placeholder circuit (x = None — Groth16 setup
    // does not look at the witness; only the constraint structure).
    let pk: ProvingKey<E> = Groth16::<E>::generate_random_parameters_with_reduction(
        SquareCircuit::<E::ScalarField> {
            x: None,
            y: E::ScalarField::from(0u64),
        },
        &mut rng,
    )?;

    let matrices = collect_matrices::<E::ScalarField, _>(SquareCircuit::<E::ScalarField> {
        x: None,
        y: E::ScalarField::from(0u64),
    })?;
    let arcs = ArcsFile::<E::ScalarField>::from_matrices(curve_id, &matrices);
    let arzkey = ArzkeyFile::<E>::from_setup_output(arcs, pk);

    // SquareCircuit wire layout: [ONE, y (instance), x (witness)].
    let full_assignment: Vec<E::ScalarField> = vec![E::ScalarField::ONE, y, x];

    let proof = prove(&arzkey, &full_assignment, &mut rng)?;
    let ok = verify(&arzkey, &[y], &proof)?;
    Ok(ok)
}

fn main() -> Result<(), Box<dyn Error>> {
    let bn254_ok = run_curve::<Bn254>(CurveId::Bn254, 3)?;
    println!(
        "BN254       (CurveId=0x{:02x}): verify → {bn254_ok}",
        CurveId::Bn254 as u8
    );
    assert!(
        bn254_ok,
        "BN254: a valid witness must produce a verifying proof"
    );

    let bls_ok = run_curve::<Bls12_381>(CurveId::Bls12_381, 17)?;
    println!(
        "BLS12-381   (CurveId=0x{:02x}): verify → {bls_ok}",
        CurveId::Bls12_381 as u8,
    );
    assert!(
        bls_ok,
        "BLS12-381: a valid witness must produce a verifying proof"
    );

    Ok(())
}
