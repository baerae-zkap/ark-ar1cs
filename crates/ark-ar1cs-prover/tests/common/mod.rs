//! Shared helpers for prover integration tests.
//!
//! `SquareCircuit<F>` is generic over the scalar field so the same
//! constraint system can drive setup on any pairing curve. Variable layout
//! (matches arkworks):
//!   index 0 — implicit "1" wire
//!   index 1 — y (public input)
//!   index 2 — x (witness)
//!
//! `setup_with_witness` (BN254) and `setup_with_witness_bls` (BLS12-381)
//! both wrap a single curve-generic `setup_with_witness_curve<E>` so the
//! curve choice is explicit at the test site (Phase D Q3 #2 cross-curve
//! coverage).
#![allow(dead_code)]

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_bn254::{Bn254, Fr as BnFr};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
    LinearCombination, OptimizationGoal, SynthesisError, SynthesisMode,
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone)]
pub struct SquareCircuit<F: PrimeField> {
    pub x: Option<F>,
    pub y: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SquareCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let y_var = cs.new_input_variable(|| Ok(self.y))?;
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var),
            LinearCombination::from(y_var),
        )?;
        Ok(())
    }
}

pub fn seeded_rng() -> StdRng {
    StdRng::from_seed([42u8; 32])
}

/// Re-synthesize `circuit` in `Setup` mode and pull `ConstraintMatrices`.
pub fn collect_matrices<F, C>(circuit: C) -> ConstraintMatrices<F>
where
    F: PrimeField,
    C: ConstraintSynthesizer<F>,
{
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    cs.to_matrices().expect("to_matrices() failed")
}

/// Curve-generic e2e helper: run Groth16 setup over `E`, wrap as `.arzkey`,
/// compute `(x, y = x*x)`, wrap witness as `.arwtns`. Both artifacts share
/// the same `ar1cs_blake3` so `bind_check` passes by construction.
fn setup_with_witness_curve<E: Pairing>(
    curve_id: CurveId,
    x_value: u64,
) -> (ArzkeyFile<E>, ArwtnsFile<E::ScalarField>) {
    let x = E::ScalarField::from(x_value);
    let y = x * x;

    let pk: ProvingKey<E> = Groth16::<E>::generate_random_parameters_with_reduction(
        SquareCircuit::<E::ScalarField> {
            x: None,
            y: E::ScalarField::from(0u64),
        },
        &mut seeded_rng(),
    )
    .expect("Groth16 setup failed");

    let matrices = collect_matrices::<E::ScalarField, _>(SquareCircuit::<E::ScalarField> {
        x: None,
        y: E::ScalarField::from(0u64),
    });
    let arcs = ArcsFile::from_matrices(curve_id, &matrices);
    let ar1cs_blake3 = arcs.body_blake3();
    let arzkey = ArzkeyFile::<E>::from_setup_output(arcs, pk);

    let arwtns =
        ArwtnsFile::<E::ScalarField>::from_assignments(curve_id, ar1cs_blake3, &[y], &[x]);

    (arzkey, arwtns)
}

/// One-shot helper that runs a real Groth16 setup over BN254, packages the
/// result as an `ArzkeyFile<Bn254>`, and produces an `ArwtnsFile<Fr>`
/// carrying the witness assignments for `(x, y = x*x)`. Both artifacts
/// share the same `ar1cs_blake3` so [`bind_check`] passes by construction.
pub fn setup_with_witness(x_value: u64) -> (ArzkeyFile<Bn254>, ArwtnsFile<BnFr>) {
    setup_with_witness_curve::<Bn254>(CurveId::Bn254, x_value)
}

/// BLS12-381 mirror of [`setup_with_witness`]. Used by the Phase D Q3 #2
/// cross-curve e2e test to verify the prover, envelopes, and bind rules
/// stay correct under a second pairing curve.
pub fn setup_with_witness_bls(
    x_value: u64,
) -> (ArzkeyFile<Bls12_381>, ArwtnsFile<BlsFr>) {
    setup_with_witness_curve::<Bls12_381>(CurveId::Bls12_381, x_value)
}
