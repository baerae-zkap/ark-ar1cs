//! wasm32 fixture: chained-squaring circuit at depth 20 (~1M constraints).
//!
//! The macro emits the canonical 4 ABI exports (`wasm_alloc`, `wasm_free`,
//! `embedded_ar1cs_blake3`, `witness_generator`) so this can be loaded by
//! Node, wasmi, JavaScriptCore, etc. for the witness-generation benchmark
//! across runtimes.
//!
//! `LargeMockGenerator::Input` is `LargeMockInput { seed: u64, depth: u32 }`.
//! Pass `depth: 20` for 2^20 constraints; smaller values are useful for
//! sanity checks against the same wasm artifact.

#![no_std]
extern crate alloc;

// On non-wasm32 hosts the macro only emits the `enforce_curve_id` const
// reference (no `wasm_*` exports), so the blake3 constant is unused there.
// Silence the warning instead of cfg-gating the import.
#[allow(unused_imports)]
use ark_ar1cs_wasm_witness::mock::{LargeMockGenerator, EMBEDDED_LARGE_AR1CS_BLAKE3};

ark_ar1cs_wasm_witness::export_witness_generator!(
    generator = LargeMockGenerator,
    embedded_blake3 = EMBEDDED_LARGE_AR1CS_BLAKE3,
);
