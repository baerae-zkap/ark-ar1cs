//! Generic `ConstraintSynthesizer` → `.arwtns` witness framework with a wasm
//! export macro.
//!
//! This crate is the circuit-agnostic layer between an arkworks circuit and a
//! `.wasm` witness-generator artifact. A circuit author implements
//! [`WitnessGenerator`] over their input/circuit/error types, then invokes
//! [`export_witness_generator!`] once to emit the wasm ABI exports
//! (`wasm_alloc`, `wasm_free`, `embedded_ar1cs_blake3`, `witness_generator`).
//!
//! The host loads the resulting `.wasm`, calls `embedded_ar1cs_blake3` to
//! verify the embedded circuit identity matches its `.arzkey`, then calls
//! `witness_generator` to produce a serialized [`ArwtnsFile`] suitable for
//! `ark_ar1cs_prover::prove`.
//!
//! See `.omc/plans/2026-05-04-circuit-first-witness-wasm.md` for the design.

#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod abi;
pub mod error;
pub mod macros;
pub mod packed;

#[doc(hidden)]
pub mod ark_ar1cs_format_reexport {
    pub use ark_ar1cs_format::CurveId;
}

use ark_ar1cs_format::CurveId;
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

pub use abi::WitnessAbiCode;
pub use error::WitnessError;
pub use macros::witness_generator_native;

/// Trait every wasm witness-generator implements.
///
/// `Circuit` must produce a *fully-assigned* `ConstraintSynthesizer` — i.e.
/// every `new_witness_variable` callback returns a concrete value, never
/// `SynthesisError::AssignmentMissing`. The `ar1cs_blake3` binding is handled
/// by the macro layer (sourced from `build.rs`), not by `build_circuit`.
pub trait WitnessGenerator {
    type Field: PrimeField;
    /// Postcard-decodable app-specific input.
    type Input: serde::de::DeserializeOwned;
    /// `ConstraintSynthesizer` impl carrying the full witness assignment.
    type Circuit: ConstraintSynthesizer<Self::Field>;
    /// Domain error reported by `build_circuit`. Convertible to a wasm ABI
    /// status (`WitnessAbiCode::CircuitBuildError` for typical failures).
    type Error: Into<WitnessAbiCode> + core::fmt::Debug;

    /// Stable identifier of this circuit. Bumped when the input schema or
    /// circuit shape changes.
    const CIRCUIT_ID: &'static str;
    /// Pairing curve the circuit's scalar field corresponds to. Must match
    /// the `.arzkey` header.
    const CURVE_ID: CurveId;

    /// Locked list of public-input names. The order MUST match
    /// `arwtns.instance[..N]` produced by [`circuit_to_arwtns`].
    fn public_input_names() -> &'static [&'static str];

    /// Build a fully-assigned circuit from the decoded app input.
    fn build_circuit(input: Self::Input) -> Result<Self::Circuit, Self::Error>;
}

/// Synthesize `circuit` into a `.arwtns` blob.
///
/// Steps:
/// 1. allocate a fresh `ConstraintSystem<F>`,
/// 2. call `circuit.generate_constraints(cs)` (drives every witness callback),
/// 3. read `instance_assignment[1..]` (skip the implicit `1` wire) and
///    `witness_assignment` from the constraint system,
/// 4. wrap them in an [`ArwtnsFile`] with the supplied `curve_id` and
///    `ar1cs_blake3` binding.
///
/// The constraint system stays in the default `Prove` synthesis mode so that
/// witness assignments are tracked. `cs.finalize()` is intentionally NOT
/// called here — finalize() is a setup-time concern that turns linear
/// combinations into matrix rows; for witness extraction the per-variable
/// assignments are already populated as constraints are enforced.
pub fn circuit_to_arwtns<F, C>(
    circuit: C,
    curve_id: CurveId,
    ar1cs_blake3: [u8; 32],
) -> Result<ArwtnsFile<F>, WitnessError>
where
    F: PrimeField,
    C: ConstraintSynthesizer<F>,
{
    let cs = ConstraintSystem::<F>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(WitnessError::Synthesis)?;

    let cs_inner = cs.borrow().ok_or(WitnessError::ConstraintSystemUnavailable)?;
    if cs_inner.instance_assignment.is_empty() {
        return Err(WitnessError::MissingOneWire);
    }
    let instance: alloc::vec::Vec<F> = cs_inner.instance_assignment[1..].to_vec();
    let witness: alloc::vec::Vec<F> = cs_inner.witness_assignment.clone();
    drop(cs_inner);

    Ok(ArwtnsFile::from_assignments(
        curve_id,
        ar1cs_blake3,
        &instance,
        &witness,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};

    /// Toy circuit: enforces `x * y == z` where `(x, y)` is the witness and
    /// `z` is a single public input.
    #[derive(Clone)]
    struct MockCircuit<F: PrimeField> {
        x: F,
        y: F,
        z: F,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for MockCircuit<F> {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<F>,
        ) -> Result<(), SynthesisError> {
            let z = cs.new_input_variable(|| Ok(self.z))?;
            let x = cs.new_witness_variable(|| Ok(self.x))?;
            let y = cs.new_witness_variable(|| Ok(self.y))?;
            cs.enforce_constraint(
                LinearCombination::from(x),
                LinearCombination::from(y),
                LinearCombination::from(z),
            )?;
            Ok(())
        }
    }

    #[test]
    fn circuit_to_arwtns_matches_assignments() {
        let x = Fr::from(7u64);
        let y = Fr::from(11u64);
        let z = x * y;
        let blake3 = [0x42u8; 32];
        let arwtns = circuit_to_arwtns(
            MockCircuit { x, y, z },
            CurveId::Bn254,
            blake3,
        )
        .expect("circuit_to_arwtns failed");

        assert_eq!(arwtns.header.curve_id as u8, CurveId::Bn254 as u8);
        assert_eq!(arwtns.header.ar1cs_blake3, blake3);
        assert_eq!(arwtns.instance, alloc::vec![z]);
        assert_eq!(arwtns.witness, alloc::vec![x, y]);
        assert_eq!(arwtns.header.num_instance, 1);
        assert_eq!(arwtns.header.num_witness, 2);
    }

    #[test]
    fn circuit_to_arwtns_round_trips_through_arwtns_file() {
        let x = Fr::from(3u64);
        let y = Fr::from(5u64);
        let z = x * y;
        let blake3 = [0x99u8; 32];
        let arwtns = circuit_to_arwtns(
            MockCircuit { x, y, z },
            CurveId::Bn254,
            blake3,
        )
        .unwrap();

        let mut buf = alloc::vec::Vec::new();
        arwtns.write(&mut buf).unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        let parsed: ArwtnsFile<Fr> = ArwtnsFile::read(&mut cursor).unwrap();
        assert_eq!(parsed, arwtns);
    }
}
