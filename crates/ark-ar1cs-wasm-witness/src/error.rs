//! Re-export of the core [`ark_ar1cs::WitnessError`] for callers that still
//! reach for `ark_ar1cs_wasm_witness::error::WitnessError`.
//!
//! The enum and its impls live in the runtime crate (`ark-ar1cs`) so the
//! `.ar1cs` codec / prove primitive owns the witness error type. This module
//! exists only as a transitional alias — the upcoming Commit 7 of the
//! feature-boundary migration deletes this crate entirely; callers should
//! migrate their imports to `ark_ar1cs::WitnessError`.
//!
//! No `impl From<WitnessError> for WitnessAbiCode` lives here: the wasm ABI
//! conversion is inlined at the two `macros` call sites (orphan-rule
//! workaround per `docs/feature-boundary-locked.md` §"Implementation Notes"
//! §1 option (c)).

pub use ark_ar1cs::WitnessError;
