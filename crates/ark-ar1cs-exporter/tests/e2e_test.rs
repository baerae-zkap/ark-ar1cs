/// End-to-end test: export → import → generate_parameters produces identical proving keys.
///
/// Circuit: prove knowledge of x such that x * x = y  (y is a public input)
///   - num_instance_variables = 2 (implicit "1" wire + y)
///   - num_witness_variables  = 1 (x)
///   - num_constraints        = 1 (x * x = y)
use ark_ar1cs_exporter::export_circuit;
use ark_ar1cs_format::CurveId;
use ark_ar1cs_importer::ImportedCircuit;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use rand::{rngs::StdRng, SeedableRng};

// ---------------------------------------------------------------------------
// Test circuit
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SquareCircuit {
    /// Secret witness x.  `None` in setup mode.
    x: Option<Fr>,
    /// Public input y = x^2.
    y: Fr,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate witness x
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        // Allocate public input y
        let y_var = cs.new_input_variable(|| Ok(self.y))?;
        // Enforce x * x = y
        cs.enforce_constraint(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var),
            LinearCombination::from(y_var),
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn seeded_rng() -> StdRng {
    StdRng::from_seed([42u8; 32])
}

fn setup_circuit() -> SquareCircuit {
    // In setup mode the closures aren't called; values don't matter.
    SquareCircuit { x: None, y: Fr::from(0u64) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The exported file must produce the same ConstraintMatrices as direct synthesis.
#[test]
fn exported_matrices_match_original() {
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer, OptimizationGoal, SynthesisMode};

    // Synthesize directly
    let cs1 = ConstraintSystem::<Fr>::new_ref();
    cs1.set_optimization_goal(OptimizationGoal::Constraints);
    cs1.set_mode(SynthesisMode::Setup);
    setup_circuit().generate_constraints(cs1.clone()).unwrap();
    cs1.finalize();
    let matrices_direct = cs1.to_matrices().unwrap();

    // Export → import → synthesize
    let mut buf = Vec::new();
    export_circuit::<Fr, _, _>(setup_circuit(), CurveId::Bn254, &mut buf).unwrap();
    let imported = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice()).unwrap();

    let cs2 = ConstraintSystem::<Fr>::new_ref();
    cs2.set_optimization_goal(OptimizationGoal::Constraints);
    cs2.set_mode(SynthesisMode::Setup);
    imported.generate_constraints(cs2.clone()).unwrap();
    cs2.finalize();
    let matrices_imported = cs2.to_matrices().unwrap();

    assert_eq!(matrices_direct.num_instance_variables, matrices_imported.num_instance_variables);
    assert_eq!(matrices_direct.num_witness_variables,  matrices_imported.num_witness_variables);
    assert_eq!(matrices_direct.num_constraints,        matrices_imported.num_constraints);
    assert_eq!(matrices_direct.a, matrices_imported.a, "matrix A");
    assert_eq!(matrices_direct.b, matrices_imported.b, "matrix B");
    assert_eq!(matrices_direct.c, matrices_imported.c, "matrix C");
}

/// Groth16 proving keys generated from the original circuit and from the
/// imported circuit (using the same seeded RNG) must be identical.
#[test]
fn proving_keys_match() {
    // --- setup from original circuit ---
    let pk_original = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut seeded_rng(),
    )
    .expect("setup from original circuit failed");

    // --- export ---
    let mut buf = Vec::new();
    export_circuit::<Fr, _, _>(setup_circuit(), CurveId::Bn254, &mut buf)
        .expect("export failed");

    // --- setup from imported circuit (same seed) ---
    let imported = ImportedCircuit::<Fr>::from_reader(&mut buf.as_slice())
        .expect("import failed");
    let pk_imported = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        imported,
        &mut seeded_rng(),  // identical seed → identical toxic waste
    )
    .expect("setup from imported circuit failed");

    // Proving keys must be byte-for-byte equal.
    assert_eq!(pk_original, pk_imported, "proving keys differ");
}
