//! Shared helpers for prover integration tests.
//!
//! `SquareCircuit` mirrors the fixture used in the exporter e2e tests:
//! prove knowledge of `x` such that `x * x = y`, with `y` as the public input.
//! Variable layout (matches arkworks):
//!   index 0 — implicit "1" wire
//!   index 1 — y (public input)
//!   index 2 — x (witness)
#![allow(dead_code)]

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
    LinearCombination, OptimizationGoal, SynthesisError, SynthesisMode,
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone)]
pub struct SquareCircuit {
    pub x: Option<Fr>,
    pub y: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
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

/// Re-synthesize the circuit in `Setup` mode and pull `ConstraintMatrices`.
pub fn collect_matrices<C: ConstraintSynthesizer<Fr>>(circuit: C) -> ConstraintMatrices<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    cs.to_matrices().expect("to_matrices() failed")
}

/// One-shot helper that runs a real Groth16 setup, packages the result as an
/// `ArzkeyFile<Bn254>`, and produces an `ArwtnsFile<Fr>` carrying the witness
/// assignments for `(x, y = x*x)`. Both artifacts share the same
/// `ar1cs_blake3` so [`bind_check`] passes by construction.
pub fn setup_with_witness(x_value: u64) -> (ArzkeyFile<Bn254>, ArwtnsFile<Fr>) {
    let x = Fr::from(x_value);
    let y = x * x;

    let pk: ProvingKey<Bn254> = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        SquareCircuit {
            x: None,
            y: Fr::from(0u64),
        },
        &mut seeded_rng(),
    )
    .expect("Groth16 setup failed");

    let matrices = collect_matrices(SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    });
    let arcs = ArcsFile::from_matrices(CurveId::Bn254, &matrices);
    let ar1cs_blake3 = arcs.body_blake3();
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);

    let arwtns = ArwtnsFile::<Fr>::from_assignments(CurveId::Bn254, ar1cs_blake3, &[y], &[x]);

    (arzkey, arwtns)
}
