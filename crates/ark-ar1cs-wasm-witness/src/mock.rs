//! Test/benchmark fixtures: concrete `WitnessGenerator` impls over BN254 Fr.
//!
//! Two circuits live here:
//!
//! - **`MockCircuit`** — single multiplication `x * y == z`. Used by inline
//!   unit tests and by the wasmi smoke fixture
//!   (`tests/fixtures/mock-witness-fixture/`).
//!
//! - **`LargeMockCircuit`** — chained squaring of depth `D`, producing
//!   exactly `2^D` constraints and `2^D` witness variables. Used by the
//!   2^20 bench fixture (`tests/fixtures/large-witness-fixture/`).
//!
//! Both impls share the type `ark_bn254::Fr` and the wasm ABI shape, so
//! native and wasm execution paths can be compared byte-for-byte.

use alloc::vec::Vec;

use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use serde::{Deserialize, Serialize};

use ark_ar1cs_format::CurveId;

use crate::abi::WitnessAbiCode;
use crate::WitnessGenerator;

// ---------------------------------------------------------------------------
// Shared fixture-side blake3 constants.
// ---------------------------------------------------------------------------

/// `embedded_ar1cs_blake3` value baked into the small wasm fixture. Pure
/// fiction — these fixtures don't have a real `.arzkey` to bind against.
pub const EMBEDDED_AR1CS_BLAKE3: [u8; 32] = [0x42; 32];

/// `embedded_ar1cs_blake3` value baked into the large (2^20) wasm fixture.
/// Distinct from the small fixture's so a host can't accidentally feed the
/// wrong wasm against the wrong host blake3.
pub const EMBEDDED_LARGE_AR1CS_BLAKE3: [u8; 32] = [0x44; 32];

// ---------------------------------------------------------------------------
// Small fixture: x * y == z.
// ---------------------------------------------------------------------------

/// Postcard-decodable input for [`MockGenerator`].
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MockInput {
    pub x: u64,
    pub y: u64,
}

/// Toy circuit: enforces `x * y == z` where `(x, y)` is the witness and
/// `z` is a single public input. Same shape as the historical inline test
/// circuit at `lib.rs:131-146` of an earlier revision.
#[derive(Clone)]
pub struct MockCircuit {
    pub x: Fr,
    pub y: Fr,
    pub z: Fr,
}

impl ConstraintSynthesizer<Fr> for MockCircuit {
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

/// Domain error type for [`MockGenerator`] — collapses into
/// [`WitnessAbiCode::CircuitBuildError`].
#[derive(Debug)]
pub struct MockError;

impl From<MockError> for WitnessAbiCode {
    fn from(_: MockError) -> Self {
        WitnessAbiCode::CircuitBuildError
    }
}

/// `WitnessGenerator` for [`MockCircuit`].
pub struct MockGenerator;

impl WitnessGenerator for MockGenerator {
    type Field = Fr;
    type Input = MockInput;
    type Circuit = MockCircuit;
    type Error = MockError;

    const CIRCUIT_ID: &'static str = "mock-witness-test-v0";
    const CURVE_ID: CurveId = CurveId::Bn254;

    fn public_input_names() -> &'static [&'static str] {
        &["z"]
    }

    fn build_circuit(input: MockInput) -> Result<MockCircuit, MockError> {
        let x = Fr::from(input.x);
        let y = Fr::from(input.y);
        Ok(MockCircuit { x, y, z: x * y })
    }
}

// ---------------------------------------------------------------------------
// Large fixture: chained squaring at depth D → 2^D constraints.
// ---------------------------------------------------------------------------

/// Default depth for benchmark / measurement runs. `2^20 == 1_048_576`
/// constraints, on the scale of anon-aadhaar-class circuits.
pub const LARGE_CIRCUIT_DEFAULT_DEPTH: u32 = 20;

/// Postcard-decodable input for [`LargeMockGenerator`].
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LargeMockInput {
    /// Initial value `x_0`.
    pub seed: u64,
    /// Number of squarings. Constraint count == `1 << depth`.
    pub depth: u32,
}

/// Chained-squaring circuit: `x_0 = seed`, `x_{i+1} = x_i^2`, public input
/// is `x_N` where `N == 2^depth`. Yields exactly `N` R1CS constraints and
/// `N` witness variables (`x_0 .. x_{N-1}`) with one instance variable
/// (`x_N`).
///
/// Field-op flavor matches a typical witness-heavy ZK circuit: BN254 Fr
/// multiplication is the dominant cost, no SHA/Poseidon overhead. Pure
/// arithmetic isolates the wasm-vs-native overhead we want to measure.
#[derive(Clone)]
pub struct LargeMockCircuit {
    pub seed: Fr,
    pub depth: u32,
}

impl ConstraintSynthesizer<Fr> for LargeMockCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let n: u64 = 1u64 << self.depth;
        // Pre-compute `x_0 .. x_N` so we can allocate the public input
        // (which arkworks requires before any witness) with the final
        // value, then walk the witnesses in order. Vec is dropped before
        // we leave generate_constraints, peak transient ≈ N * 32 bytes
        // (32 MiB at depth=20).
        let mut values: Vec<Fr> = Vec::with_capacity(n as usize + 1);
        values.push(self.seed);
        for i in 0..n as usize {
            let next = values[i].square();
            values.push(next);
        }
        let final_value = values[n as usize];

        // Allocate public input (x_N) first.
        let final_var = cs.new_input_variable(|| Ok(final_value))?;

        // Allocate N witness variables for x_0 .. x_{N-1}.
        let mut witness_vars = Vec::with_capacity(n as usize);
        for &v in values.iter().take(n as usize) {
            let var = cs.new_witness_variable(move || Ok(v))?;
            witness_vars.push(var);
        }

        // Enforce: x_i * x_i == x_{i+1} for i in 0..N-1.
        for i in 0..(n as usize - 1) {
            cs.enforce_r1cs_constraint(
                || LinearCombination::from(witness_vars[i]),
                || LinearCombination::from(witness_vars[i]),
                || LinearCombination::from(witness_vars[i + 1]),
            )?;
        }
        // Final constraint closes the chain: x_{N-1} * x_{N-1} == x_N.
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(witness_vars[n as usize - 1]),
            || LinearCombination::from(witness_vars[n as usize - 1]),
            || LinearCombination::from(final_var),
        )?;
        Ok(())
    }
}

/// `WitnessGenerator` for [`LargeMockCircuit`].
pub struct LargeMockGenerator;

impl WitnessGenerator for LargeMockGenerator {
    type Field = Fr;
    type Input = LargeMockInput;
    type Circuit = LargeMockCircuit;
    type Error = MockError;

    const CIRCUIT_ID: &'static str = "large-mock-2pow20-v0";
    const CURVE_ID: CurveId = CurveId::Bn254;

    fn public_input_names() -> &'static [&'static str] {
        &["x_final"]
    }

    fn build_circuit(input: LargeMockInput) -> Result<LargeMockCircuit, MockError> {
        if input.depth > 24 {
            // Cap to keep accidental misuse from blowing memory: 2^24 wires
            // ≈ 512 MiB just for assignments. Real bench runs use 20.
            return Err(MockError);
        }
        Ok(LargeMockCircuit {
            seed: Fr::from(input.seed),
            depth: input.depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;

    /// Tiny depth so the test is fast. Verifies the constraint accounting
    /// without paying for 2^20.
    #[test]
    fn large_circuit_constraint_count_matches_depth() {
        const D: u32 = 4; // 2^4 == 16 constraints
        let circuit = LargeMockCircuit {
            seed: Fr::from(3u64),
            depth: D,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let inner = cs.borrow().unwrap();
        assert_eq!(inner.num_constraints(), 1usize << D);
        // N witnesses (x_0 .. x_{N-1}) — instance variable count is 2:
        // implicit one-wire + x_final.
        assert_eq!(inner.num_witness_variables(), 1usize << D);
        assert_eq!(inner.num_instance_variables(), 2);
    }

    #[test]
    fn large_circuit_witness_assignment_well_formed() {
        const D: u32 = 4;
        let seed = Fr::from(2u64);
        let circuit = LargeMockCircuit { seed, depth: D };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let inner = cs.borrow().unwrap();
        // x_0 == seed
        assert_eq!(inner.assignments.witness_assignment[0], seed);
        // x_1 == seed^2
        assert_eq!(inner.assignments.witness_assignment[1], seed.square());
        // public input (after the implicit one-wire) is x_N == seed^(2^N)
        let mut expected_final = seed;
        for _ in 0..(1u32 << D) {
            expected_final = expected_final.square();
        }
        assert_eq!(inner.assignments.instance_assignment[1], expected_final);
    }

    #[test]
    fn large_generator_rejects_excessive_depth() {
        let err = LargeMockGenerator::build_circuit(LargeMockInput { seed: 1, depth: 25 });
        assert!(err.is_err());
    }

    /// End-to-end native path: postcard → witness_generator_native →
    /// `Vec<F>` ark-serialize round-trip. Mirrors what the wasm fixture does
    /// at runtime, but on the host. Tiny depth keeps the test fast.
    #[test]
    fn large_generator_native_path_round_trips() {
        use crate::macros::witness_generator_native;
        use ark_serialize::CanonicalDeserialize;

        let depth: u32 = 4;
        let n: usize = 1usize << depth;
        let input = LargeMockInput { seed: 3, depth };
        let bytes = postcard::to_allocvec(&input).unwrap();
        let witness_bytes = witness_generator_native::<LargeMockGenerator>(
            &bytes,
            &EMBEDDED_LARGE_AR1CS_BLAKE3,
            &EMBEDDED_LARGE_AR1CS_BLAKE3,
        )
        .expect("native witness gen failed");

        let full: Vec<Fr> = Vec::<Fr>::deserialize_compressed(witness_bytes.as_slice())
            .expect("vec<Fr> read failed");

        // Layout: [F::ONE, instance (1 element: x_N), witness (n elements: x_0..x_{N-1})].
        assert_eq!(full.len(), 1 + 1 + n);
        assert_eq!(full[0], Fr::from(1u64));
        // x_N (instance) == seed^(2^N)
        let mut expected_final = Fr::from(3u64);
        for _ in 0..n {
            expected_final = expected_final.square();
        }
        assert_eq!(full[1], expected_final);
        // x_0 == seed (first witness)
        assert_eq!(full[2], Fr::from(3u64));
    }
}
