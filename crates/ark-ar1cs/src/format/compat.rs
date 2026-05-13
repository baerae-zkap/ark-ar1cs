//! Compatibility shim for `ark_relations::r1cs::ConstraintMatrices`, which
//! was removed in ark-relations 0.6 when the R1CS module became GR1CS.
//!
//! The 0.6 equivalent is `cs.to_matrices()? -> BTreeMap<Label, Vec<Matrix<F>>>`,
//! keyed by predicate label, with variable / constraint counts queried
//! separately on `ConstraintSystemRef`. This shim flattens that back into a
//! struct matching the 0.5 field layout so the existing `.ar1cs` schema and
//! export/import path can stay unchanged.
use ark_ff::PrimeField;
use ark_relations::gr1cs::{
    ConstraintSystemRef, Result as Gr1csResult, SynthesisError, R1CS_PREDICATE_LABEL,
};

use crate::format::matrix::Matrix;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintMatrices<F: PrimeField> {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a_num_non_zero: usize,
    pub b_num_non_zero: usize,
    pub c_num_non_zero: usize,
    pub a: Matrix<F>,
    pub b: Matrix<F>,
    pub c: Matrix<F>,
}

impl<F: PrimeField> ConstraintMatrices<F> {
    /// Project the GR1CS predicate-keyed matrix map down to the R1CS triple
    /// and pair it with the per-CS variable / constraint counts.
    pub fn from_cs(cs: &ConstraintSystemRef<F>) -> Gr1csResult<Self> {
        let mut all = cs.to_matrices()?;
        let mut r1cs = all
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or(SynthesisError::AssignmentMissing)?;
        if r1cs.len() != 3 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let c = r1cs.pop().unwrap();
        let b = r1cs.pop().unwrap();
        let a = r1cs.pop().unwrap();
        let a_num_non_zero = a.iter().map(|r| r.len()).sum();
        let b_num_non_zero = b.iter().map(|r| r.len()).sum();
        let c_num_non_zero = c.iter().map(|r| r.len()).sum();
        Ok(Self {
            num_instance_variables: cs.num_instance_variables(),
            num_witness_variables: cs.num_witness_variables(),
            num_constraints: cs.num_constraints(),
            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero,
            a,
            b,
            c,
        })
    }
}
