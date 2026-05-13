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
//! As of the feature-boundary migration's Commit 3, the generic
//! [`synthesize_full_assignment`] helper and the
//! [`WitnessError`] type live in `ark-ar1cs` core. This crate keeps the
//! historical paths working (`ark_ar1cs_wasm_witness::synthesize_full_assignment`,
//! `ark_ar1cs_wasm_witness::WitnessError`) as transitional re-exports until
//! Commit 7 deletes the crate.

// Workspace policy enforces `unsafe_code = "deny"`. The wasm ABI files
// (`abi.rs`, `macros.rs`) opt back in via file-level `#![allow(unsafe_code)]`.
// Keep the stricter `unsafe_op_in_unsafe_fn` lint here — it isn't part of
// the workspace policy — so every `unsafe { ... }` block stays explicit.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

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
use ark_relations::gr1cs::ConstraintSynthesizer;

pub use abi::WitnessAbiCode;
pub use ark_ar1cs::{synthesize_full_assignment, WitnessError};
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
