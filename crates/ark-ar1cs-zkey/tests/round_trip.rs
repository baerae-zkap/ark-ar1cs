/// `.arzkey` happy-path round-trip test on BN254.
///
/// Synthesize a small SquareCircuit (x*x = y), run Groth16 setup, wrap as
/// ArzkeyFile via from_setup_output, write to bytes, read back, assert the
/// recovered VK and PK equal the originals.
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    OptimizationGoal, SynthesisError, SynthesisMode,
};

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

fn setup_circuit() -> SquareCircuit {
    SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    }
}

fn extract_arcs() -> ArcsFile<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    setup_circuit().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices)
}

#[test]
fn round_trip_bn254() {
    let mut rng = ark_std::test_rng();

    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng,
    )
    .expect("Groth16 setup failed");

    let arcs = extract_arcs();
    let original = ArzkeyFile::<Bn254>::from_setup_output(arcs.clone(), pk.clone());

    let mut buf = Vec::new();
    original.write(&mut buf).expect("write failed");

    let recovered =
        ArzkeyFile::<Bn254>::read(&mut buf.as_slice()).expect("read failed");

    assert_eq!(original.header, recovered.header, "header mismatch");
    assert_eq!(original.arcs, recovered.arcs, "embedded arcs mismatch");
    assert_eq!(original.vk, recovered.vk, "VK mismatch");
    assert_eq!(original.pk, recovered.pk, "PK mismatch");
}

#[test]
fn from_setup_output_derives_vk_from_pk() {
    let mut rng = ark_std::test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng,
    )
    .unwrap();

    let arcs = extract_arcs();
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk.clone());

    // ARCH-3 — arzkey.vk MUST equal pk.vk by construction. Drift class
    // structurally closed.
    assert_eq!(arzkey.vk, pk.vk);
    assert_eq!(arzkey.pk.vk, arzkey.vk);
}

#[test]
fn validate_passes_after_construction() {
    let mut rng = ark_std::test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng,
    )
    .unwrap();
    let arcs = extract_arcs();
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);
    arzkey.validate().expect("validate should pass");
}

#[test]
fn vk_extraction_via_serialize_compressed() {
    use ark_serialize::CanonicalSerialize;

    let mut rng = ark_std::test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit(),
        &mut rng,
    )
    .unwrap();
    let arcs = extract_arcs();
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);

    // CQ-1 — no write_vk_only helper. Raw VK bytes come from one line:
    let mut vk_bytes = Vec::new();
    arzkey.vk().serialize_compressed(&mut vk_bytes).unwrap();
    assert_eq!(
        vk_bytes.len() as u64,
        arzkey.header.vk_byte_len,
        "serialized VK size must match header.vk_byte_len"
    );
}
