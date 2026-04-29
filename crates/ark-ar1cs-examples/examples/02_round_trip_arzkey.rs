//! Byte-identical round-trip of a `.arzkey` artifact.
//!
//! Demonstrates `read(write(x)) == x` at the byte level for an
//! `ArzkeyFile<Bn254>` produced by `from_setup_output`. This is the
//! determinism property that the proptest at
//! `crates/ark-ar1cs-zkey/tests/proptest.rs` validates statistically;
//! this example shows the property concretely on one fixture circuit.
//!
//! The workflow also shows the trailer integrity contract: the second
//! `write` regenerates the Blake3 trailer from scratch, and the bytes
//! match the first write because the body — header + .ar1cs + vk + pk —
//! is canonically serialized.

use std::error::Error;

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    OptimizationGoal, SynthesisError, SynthesisMode,
};
use rand::{rngs::StdRng, SeedableRng};

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

fn build_arzkey() -> Result<ArzkeyFile<Bn254>, Box<dyn Error>> {
    // Single, deterministic seed so repeated runs of this example produce
    // the same proving key (and therefore the same .arzkey bytes).
    let mut rng = StdRng::from_seed([1u8; 32]);

    let setup_circuit = SquareCircuit {
        x: None,
        y: Fr::from(0u64),
    };
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        setup_circuit.clone(),
        &mut rng,
    )?;

    // Re-synthesize once in Setup mode to extract the matrices.
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    setup_circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let matrices = cs
        .to_matrices()
        .ok_or("ConstraintSystem::to_matrices returned None")?;

    let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);
    Ok(ArzkeyFile::<Bn254>::from_setup_output(arcs, pk))
}

fn main() -> Result<(), Box<dyn Error>> {
    let original = build_arzkey()?;
    println!(
        "[1/4] arzkey built     → header_size+body+trailer (vk_byte_len={})",
        original.header.vk_byte_len,
    );

    // First write — the canonical byte sequence for this ArzkeyFile.
    let mut bytes_first = Vec::new();
    original.write(&mut bytes_first)?;
    println!("[2/4] write → bytes    → {} bytes", bytes_first.len());

    // Read the bytes back. read() verifies the Blake3 trailer, slices
    // the body by the header's three length fields, and runs the four
    // structural checks (ar1cs_blake3, vk_blake3, vk_duplication, count
    // mirrors) before returning Ok.
    let parsed = ArzkeyFile::<Bn254>::read(&mut &bytes_first[..])?;
    println!("[3/4] read → ArzkeyFile → header.ar1cs_blake3 authenticated");

    // Second write — must produce the exact same bytes as the first.
    let mut bytes_second = Vec::new();
    parsed.write(&mut bytes_second)?;
    assert_eq!(
        bytes_first, bytes_second,
        "round-trip determinism: read(write(x)) must produce byte-identical output"
    );
    println!(
        "[4/4] byte-equal       → {} bytes match across write→read→write",
        bytes_second.len()
    );

    // The structural invariants survive the round-trip too.
    assert_eq!(parsed.header, original.header);
    assert_eq!(parsed.vk(), original.vk());
    println!("       structural ok   → header + VK match the original");

    Ok(())
}
