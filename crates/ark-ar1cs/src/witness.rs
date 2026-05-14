//! Generic `ConstraintSynthesizer → full-assignment vector` helper.
//!
//! [`synthesize_full_assignment`] runs a fully-assigned
//! [`ConstraintSynthesizer<F>`] against a fresh `ConstraintSystem<F>` in
//! `SynthesisMode::Prove { construct_matrices: false }` and returns the
//! prover-shaped vector `[F::ONE, instance..., witness...]` — the exact
//! layout [`crate::prove`] expects.
//!
//! ## Layout invariant
//!
//! The returned `Vec<F>` is laid out as:
//!
//! ```text
//!   index 0                   F::ONE                       — the implicit 1-wire
//!   index 1..num_instance     circuit's public inputs       — same order as
//!                                                            `cs.instance_assignment[1..]`
//!   index num_instance..end   circuit's witness variables   — `cs.witness_assignment`
//! ```
//!
//! and its length is exactly `num_instance + num_witness` (which equals
//! `1 + (num_instance - 1) + num_witness`).
//!
//! ## Caller responsibility
//!
//! This helper does **not** preflight the R1CS — i.e. it does not check
//! that `Az ⊙ Bz == Cz`. That check runs inside [`crate::prove`]
//! ([`crate::ProverError::AssignmentNotSatisfying`] on the first violating
//! row) so the witness helper stays usable for callers that want the
//! assignment without immediately proving (e.g. to serialize the witness,
//! to compare against a reference, or to feed it to an off-host prover).
//!
//! ## Why this lives in `ark-ar1cs` core
//!
//! Every consumer of `.ar1cs` + [`crate::prove`] needs to build a full
//! assignment from some circuit somewhere; the helper is generic over
//! `C: ConstraintSynthesizer<F>` and makes no wasm or transport
//! assumptions. Wasm-specific witness export (postcard-decoded input,
//! ABI status codes, `WitnessAbiCode`) lives one layer up in
//! `ark-ar1cs-wasm-witness` — there is no wasm dependency in this
//! module.
//!
//! ## Error semantics
//!
//! [`WitnessError`] separates the four failure paths:
//!
//! * [`WitnessError::Synthesis`] — `generate_constraints` returned
//!   `Err(SynthesisError::_)`. Wrap arkworks's error so callers can match
//!   on it without depending on the `ark-relations` enum directly.
//! * [`WitnessError::ConstraintSystemUnavailable`] — the fresh
//!   `ConstraintSystemRef::borrow` returned `None`. Should not happen for
//!   the fresh-cs-per-call pattern used here; surfaced as a typed error
//!   instead of a panic.
//! * [`WitnessError::MissingOneWire`] — `instance_assignment` was empty
//!   (no implicit 1-wire at index 0). Indicates the circuit synthesizer
//!   did not actually run.
//! * [`WitnessError::Serialize`] — `ark_serialize` round-trip failure
//!   surfaced by helpers that wrap this function with serialization.
//!
//! ABI-status conversion (e.g. mapping every variant to
//! `WitnessAbiCode::CircuitBuildError`) is the caller's concern. The
//! variant set is `#[non_exhaustive]` so external crates must include a
//! catch-all arm.

use ark_ff::PrimeField;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError, SynthesisMode,
};

/// Errors raised by [`synthesize_full_assignment`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// `ConstraintSynthesizer::generate_constraints` failed.
    #[error("constraint synthesis failed: {0}")]
    Synthesis(SynthesisError),

    /// `ConstraintSystemRef::borrow` returned `None` (the cs was dropped or
    /// already mutably borrowed). Should not occur for the
    /// fresh-cs-per-call pattern this helper uses.
    #[error("constraint system borrow unavailable")]
    ConstraintSystemUnavailable,

    /// `instance_assignment` was empty — no implicit `1` wire present.
    /// Indicates the circuit synthesizer did not run, since the cs always
    /// pre-seeds index 0 with `F::ONE`.
    #[error("constraint system missing implicit 1-wire at index 0")]
    MissingOneWire,

    /// Witness `Vec<F>` serialization failed downstream (helper paths that
    /// wrap [`synthesize_full_assignment`] with `ark-serialize`).
    #[error("witness serialize: {0}")]
    Serialize(#[from] ark_serialize::SerializationError),
}

/// Synthesize `circuit` into the prover-shaped full assignment vector
/// `[F::ONE, instance..., witness...]`.
///
/// Steps:
/// 1. Allocate a fresh `ConstraintSystem<F>` and switch it to
///    `SynthesisMode::Prove { construct_matrices: false }`.
/// 2. Call `circuit.generate_constraints(cs)` (drives every witness callback).
/// 3. Read `instance_assignment[1..]` (skip the implicit `1` wire) and
///    `witness_assignment` from the constraint system.
/// 4. Return `[F::ONE, instance..., witness...]`.
///
/// `construct_matrices: false` skips A/B/C row accumulation inside
/// `enforce_constraint`: those matrices already live in `.ar1cs` and
/// rebuilding them here would be wasted work. Witness/instance
/// assignments are still populated because the mode is `Prove`, not
/// `Setup` (arkworks 0.5.1 `constraint_system.rs:234` gates
/// assignment-push on `!is_in_setup_mode()`). `cs.finalize()` is
/// intentionally NOT called — finalize turns linear combinations into
/// matrix rows, which is a setup-time concern.
pub fn synthesize_full_assignment<C, F>(circuit: C) -> Result<Vec<F>, WitnessError>
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
    let mut full: Vec<F> = Vec::with_capacity(num_instance + num_witness);
    full.push(F::ONE);
    full.extend_from_slice(&cs_inner.assignments.instance_assignment[1..]);
    full.extend_from_slice(&cs_inner.assignments.witness_assignment);
    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Field;
    use ark_relations::gr1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// `x * y = z`, z public, x and y witness. Smallest fully-assigned
    /// circuit that exercises both instance and witness pathways.
    struct MockCircuit {
        x: Fr,
        y: Fr,
        z: Fr,
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

    /// `generate_constraints` immediately returns an arkworks
    /// `SynthesisError`. Used by B4 to validate the typed-error path.
    struct FailingCircuit;

    impl<F: PrimeField> ConstraintSynthesizer<F> for FailingCircuit {
        fn generate_constraints(self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            Err(SynthesisError::AssignmentMissing)
        }
    }

    /// B1 — layout `[F::ONE, instance..., witness...]`.
    #[test]
    fn synthesize_full_assignment_matches_assignments() {
        let x = Fr::from(7u64);
        let y = Fr::from(11u64);
        let z = x * y;
        let full = synthesize_full_assignment::<_, Fr>(MockCircuit { x, y, z })
            .expect("synthesize_full_assignment failed");

        assert_eq!(full.len(), 4);
        assert_eq!(full[0], Fr::ONE);
        assert_eq!(full[1], z);
        assert_eq!(full[2], x);
        assert_eq!(full[3], y);
    }

    /// B2 — output length equals `num_instance + num_witness`. For
    /// `MockCircuit`: `num_instance = 2` (the implicit 1-wire + `z`) plus
    /// `num_witness = 2` (`x`, `y`) → length 4.
    #[test]
    fn synthesize_full_assignment_length_matches_counts() {
        let x = Fr::from(2u64);
        let y = Fr::from(3u64);
        let z = x * y;
        let full = synthesize_full_assignment::<_, Fr>(MockCircuit { x, y, z }).unwrap();

        // num_instance (2: implicit-1 + z) + num_witness (2: x, y) == 4.
        assert_eq!(full.len(), 2 + 2);
    }

    /// B4 — synthesis failure surfaces as `WitnessError::Synthesis(_)`,
    /// not a panic and not a different variant.
    #[test]
    fn synthesize_full_assignment_propagates_synthesis_error() {
        let err = synthesize_full_assignment::<FailingCircuit, Fr>(FailingCircuit).unwrap_err();
        assert!(
            matches!(
                err,
                WitnessError::Synthesis(SynthesisError::AssignmentMissing)
            ),
            "got: {err:?}"
        );
    }

    /// B5 — full-assignment Vec round-trips byte-identical through
    /// `ark_serialize::{CanonicalSerialize, CanonicalDeserialize}`.
    #[test]
    fn synthesize_full_assignment_round_trips_through_ark_serialize() {
        let x = Fr::from(3u64);
        let y = Fr::from(5u64);
        let z = x * y;
        let full = synthesize_full_assignment::<_, Fr>(MockCircuit { x, y, z }).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        full.serialize_compressed(&mut buf).unwrap();
        let parsed: Vec<Fr> = Vec::<Fr>::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(parsed, full);
    }

    /// Regression guard inherited from the wasm-witness `mod tests`: the
    /// witness-only `SynthesisMode { construct_matrices: false }` path
    /// must produce the same full-assignment bytes as a default
    /// `construct_matrices: true` run.
    #[test]
    fn synthesize_full_assignment_byte_identical_to_default_prove_mode() {
        let x = Fr::from(13u64);
        let y = Fr::from(17u64);
        let z = x * y;

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
        let mut full_ref: Vec<Fr> = Vec::with_capacity(
            cs_inner.assignments.instance_assignment.len()
                + cs_inner.assignments.witness_assignment.len(),
        );
        full_ref.push(Fr::ONE);
        full_ref.extend_from_slice(&cs_inner.assignments.instance_assignment[1..]);
        full_ref.extend_from_slice(&cs_inner.assignments.witness_assignment);
        drop(cs_inner);

        assert_eq!(full_witness_only, full_ref);

        let mut a: Vec<u8> = Vec::new();
        let mut b: Vec<u8> = Vec::new();
        full_witness_only.serialize_compressed(&mut a).unwrap();
        full_ref.serialize_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }
}
