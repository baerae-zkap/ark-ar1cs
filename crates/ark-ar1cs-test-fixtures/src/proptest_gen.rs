//! Bounded `proptest` strategy that yields R1CS-satisfying matrix/assignment
//! pairs by construction. Used by every `cargo test --release` proptest in
//! `ark-ar1cs-format`, `ark-ar1cs-wtns`, and `ark-ar1cs-prover`.
//!
//! # Bounds (OV-5 #iv / Phase D)
//!
//! - `num_constraints` ∈ `1..=PROPTEST_MAX_CONSTRAINTS` (≤ 16)
//! - per-matrix non-zeros ≤ `PROPTEST_MAX_NONZEROS_PER_MATRIX` (≤ 64); single-entry
//!   rows keep the actual count at `num_constraints`, well within budget.
//!
//! Loosening these bounds blows the wall-clock budget of `prove → verify` at
//! ≥1000 iterations because `Groth16::generate_random_parameters_with_reduction`
//! cost grows superlinearly in `num_constraints`.
//!
//! # Construction strategy
//!
//! Sample the full assignment first, then derive matrices from it:
//!
//! 1. Pick `num_instance_variables` (∈ `2..=4`, includes the implicit `1` wire),
//!    `num_witness_variables` (∈ `1..=5`), and `num_constraints` (∈ `1..=16`).
//! 2. Sample `z = [F::ONE, instance..., witness...]` from `u64`-derived field
//!    elements.
//! 3. For each constraint `i`, pick `(a_idx, b_idx) ∈ [0, total_vars)²` and emit
//!    single-entry rows:
//!    - `A[i] = [(F::ONE, a_idx)]`
//!    - `B[i] = [(F::ONE, b_idx)]`
//!    - `C[i] = [(z[a_idx]·z[b_idx], 0)]`     // `0` = the implicit `1` wire
//!
//!    By construction `Az[i]·Bz[i] = z[a_idx]·z[b_idx] = Cz[i]`, so R1CS
//!    satisfaction is structural — invariants checked by
//!    `tests/proptest_generator.rs` at ≥1000 iter.
//!
//! Per `prove-must-preflight-r1cs` (10/10): a buggy generator that emits
//! non-satisfying samples would surface in downstream property tests as
//! `ProverError::AssignmentNotSatisfying`, which is the signal we use to
//! detect generator drift.

use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintMatrices;
use proptest::prelude::*;

/// Maximum `num_constraints` per OV-5 #iv. Hard cap to keep the
/// `prove → verify` proptest within the 2-minute / property wall-clock budget.
pub const PROPTEST_MAX_CONSTRAINTS: usize = 16;

/// Maximum per-matrix non-zero count per OV-5 #iv. The generator emits
/// single-entry rows so the actual count stays at `num_constraints`,
/// far below this cap.
pub const PROPTEST_MAX_NONZEROS_PER_MATRIX: usize = 64;

/// Sampled value: `(matrices, full_assignment)` where
/// `full_assignment = [F::ONE, instance..., witness...]` and
/// `Az[i]·Bz[i] == Cz[i]` holds for every row by construction.
pub type MatricesWithAssignment<F> = (ConstraintMatrices<F>, Vec<F>);

/// Returns a `proptest` strategy that yields `(matrices, full_assignment)`
/// pairs satisfying the R1CS relation by construction. See module-level docs
/// for bounds and rationale.
pub fn arb_matrices_with_assignment<F: PrimeField>(
) -> impl Strategy<Value = MatricesWithAssignment<F>> {
    (
        1usize..=3, // explicit instance vars (excludes implicit "1" wire)
        1usize..=5, // witness vars
        1usize..=PROPTEST_MAX_CONSTRAINTS,
    )
        .prop_flat_map(|(n_inst_explicit, n_wit, n_constraints)| {
            let total_vars = n_inst_explicit + 1 + n_wit;
            (
                Just(n_inst_explicit),
                Just(n_wit),
                Just(n_constraints),
                prop::collection::vec(
                    any::<u64>().prop_map(F::from),
                    n_inst_explicit + n_wit,
                ),
                prop::collection::vec((0..total_vars, 0..total_vars), n_constraints),
            )
        })
        .prop_map(
            |(n_inst_explicit, n_wit, n_constraints, rest, rows)| {
                let num_instance_variables = n_inst_explicit + 1;
                let total_vars = num_instance_variables + n_wit;
                let mut z = Vec::with_capacity(total_vars);
                z.push(F::ONE);
                z.extend_from_slice(&rest);

                let mut a = Vec::with_capacity(n_constraints);
                let mut b = Vec::with_capacity(n_constraints);
                let mut c = Vec::with_capacity(n_constraints);
                for (a_idx, b_idx) in rows {
                    a.push(vec![(F::ONE, a_idx)]);
                    b.push(vec![(F::ONE, b_idx)]);
                    let prod = z[a_idx] * z[b_idx];
                    c.push(vec![(prod, 0)]);
                }

                let matrices = ConstraintMatrices {
                    num_instance_variables,
                    num_witness_variables: n_wit,
                    num_constraints: n_constraints,
                    a_num_non_zero: n_constraints,
                    b_num_non_zero: n_constraints,
                    c_num_non_zero: n_constraints,
                    a,
                    b,
                    c,
                };

                (matrices, z)
            },
        )
}
