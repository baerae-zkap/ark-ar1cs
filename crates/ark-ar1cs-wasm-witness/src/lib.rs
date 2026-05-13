//! Generic `ConstraintSynthesizer` → full-assignment witness framework with a
//! wasm export macro.
//!
//! This crate is the circuit-agnostic layer between an arkworks circuit and a
//! `.wasm` witness-generator artifact. A circuit author implements
//! [`WitnessGenerator`] over their input/circuit/error types, then invokes
//! [`export_witness_generator!`] once to emit the wasm ABI exports
//! (`wasm_alloc`, `wasm_free`, `embedded_ar1cs_blake3`, `witness_generator`).
//!
//! The host loads the resulting `.wasm`, calls `embedded_ar1cs_blake3` to
//! verify the embedded circuit identity matches its `.arzkey`, then calls
//! `witness_generator` to produce the `Vec<F>` ark-serialize bytes of the
//! full assignment `[F::ONE, instance..., witness...]` suitable for
//! `ark_ar1cs::prove`.
//!
//! See `.omc/plans/2026-05-13-stream-1.md` §"PR 1.1" for the design.

#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod abi;
pub mod error;
pub mod macros;
#[cfg(any(test, feature = "test-mock"))]
pub mod mock;
pub mod packed;

#[doc(hidden)]
pub mod ark_ar1cs_format_reexport {
    pub use ark_ar1cs::format::CurveId;
}

use ark_ar1cs::format::CurveId;
use ark_ff::PrimeField;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};

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

    /// Locked list of public-input names. The order MUST match the
    /// `instance` slice (i.e. elements `1..=N` of the returned full
    /// assignment) produced by [`synthesize_full_assignment`].
    fn public_input_names() -> &'static [&'static str];

    /// Build a fully-assigned circuit from the decoded app input.
    fn build_circuit(input: Self::Input) -> Result<Self::Circuit, Self::Error>;
}

/// Synthesize `circuit` into the prover-shaped full assignment vector
/// `[F::ONE, instance..., witness...]`.
///
/// Steps:
/// 1. allocate a fresh `ConstraintSystem<F>` and switch it to
///    `SynthesisMode::Prove { construct_matrices: false }`,
/// 2. call `circuit.generate_constraints(cs)` (drives every witness callback),
/// 3. read `instance_assignment[1..]` (skip the implicit `1` wire) and
///    `witness_assignment` from the constraint system,
/// 4. return `[F::ONE, instance..., witness...]` — the exact layout
///    `ark_ar1cs::prove` expects.
///
/// `construct_matrices: false` skips A/B/C row accumulation in
/// `enforce_constraint` (we never read those rows here — they live in
/// `.arzkey` already). Witness/instance assignments are still populated
/// because the mode is `Prove`, not `Setup` (arkworks 0.5.1
/// `constraint_system.rs:234` gates assignment-push on
/// `!is_in_setup_mode()`). `cs.finalize()` is intentionally NOT called —
/// finalize() turns linear combinations into matrix rows, which is a
/// setup-time concern.
pub fn synthesize_full_assignment<C, F>(circuit: C) -> Result<alloc::vec::Vec<F>, WitnessError>
where
    C: ConstraintSynthesizer<F>,
    F: PrimeField,
{
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: false,
    });
    circuit
        .generate_constraints(cs.clone())
        .map_err(WitnessError::Synthesis)?;

    let cs_inner = cs
        .borrow()
        .ok_or(WitnessError::ConstraintSystemUnavailable)?;
    if cs_inner.assignments.instance_assignment.is_empty() {
        return Err(WitnessError::MissingOneWire);
    }
    let num_instance = cs_inner.assignments.instance_assignment.len();
    let num_witness = cs_inner.assignments.witness_assignment.len();
    let mut full: alloc::vec::Vec<F> = alloc::vec::Vec::with_capacity(num_instance + num_witness);
    full.push(F::ONE);
    full.extend_from_slice(&cs_inner.assignments.instance_assignment[1..]);
    full.extend_from_slice(&cs_inner.assignments.witness_assignment);
    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockCircuit;
    use ark_bn254::Fr;
    use ark_ff::Field;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    #[test]
    fn synthesize_full_assignment_matches_assignments() {
        let x = Fr::from(7u64);
        let y = Fr::from(11u64);
        let z = x * y;
        let full = synthesize_full_assignment::<_, Fr>(MockCircuit { x, y, z })
            .expect("synthesize_full_assignment failed");

        // Layout: [F::ONE, z (instance), x, y (witness)].
        assert_eq!(full.len(), 4);
        assert_eq!(full[0], Fr::ONE);
        assert_eq!(full[1], z);
        assert_eq!(full[2], x);
        assert_eq!(full[3], y);
    }

    /// Regression guard for the witness-only `SynthesisMode` change.
    ///
    /// We previously left the cs in default `Prove { construct_matrices: true }`
    /// mode, which accumulates A/B/C rows we never read. Now we flip to
    /// `construct_matrices: false`. The full-assignment output (which only
    /// depends on `instance_assignment` and `witness_assignment`) MUST be
    /// identical.
    #[test]
    fn synthesize_full_assignment_byte_identical_to_default_prove_mode() {
        use ark_relations::gr1cs::SynthesisMode;

        let x = Fr::from(13u64);
        let y = Fr::from(17u64);
        let z = x * y;

        // Path under test: synthesize_full_assignment with construct_matrices=false.
        let full_witness_only =
            synthesize_full_assignment::<_, Fr>(MockCircuit { x, y, z }).unwrap();

        // Reference path: open-coded with default construct_matrices=true.
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });
        MockCircuit { x, y, z }
            .generate_constraints(cs.clone())
            .unwrap();
        let cs_inner = cs.borrow().unwrap();
        let mut full_ref: alloc::vec::Vec<Fr> = alloc::vec::Vec::with_capacity(
            cs_inner.assignments.instance_assignment.len()
                + cs_inner.assignments.witness_assignment.len(),
        );
        full_ref.push(Fr::ONE);
        full_ref.extend_from_slice(&cs_inner.assignments.instance_assignment[1..]);
        full_ref.extend_from_slice(&cs_inner.assignments.witness_assignment);
        drop(cs_inner);

        assert_eq!(full_witness_only, full_ref);

        // Also serialize both — bytes must match.
        let mut a = alloc::vec::Vec::new();
        let mut b = alloc::vec::Vec::new();
        full_witness_only.serialize_compressed(&mut a).unwrap();
        full_ref.serialize_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn synthesize_full_assignment_round_trips_through_ark_serialize() {
        let x = Fr::from(3u64);
        let y = Fr::from(5u64);
        let z = x * y;
        let full = synthesize_full_assignment::<_, Fr>(MockCircuit { x, y, z }).unwrap();

        let mut buf = alloc::vec::Vec::new();
        full.serialize_compressed(&mut buf).unwrap();
        let parsed: alloc::vec::Vec<Fr> =
            alloc::vec::Vec::<Fr>::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(parsed, full);
    }
}
