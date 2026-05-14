//! Dump native witness_generator output bytes to stdout (binary).
//!
//! Emits the `ark-serialize`-compressed `Vec<F>` representation of the full
//! assignment `[F::ONE, instance..., witness...]`. Use to byte-compare
//! against wasm path output (G4 gate).
use ark_ar1cs_wasm_witness::macros::witness_generator_native;
use ark_ar1cs_wasm_witness::mock::{
    LargeMockGenerator, LargeMockInput, EMBEDDED_LARGE_AR1CS_BLAKE3,
};
use std::io::Write;

fn main() {
    let depth: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let input = LargeMockInput { seed: 3, depth };
    let bytes = postcard::to_allocvec(&input)
        .expect("postcard::to_allocvec on a Serialize-derive type cannot fail");
    let witness_bytes = witness_generator_native::<LargeMockGenerator>(
        &bytes,
        &EMBEDDED_LARGE_AR1CS_BLAKE3,
        &EMBEDDED_LARGE_AR1CS_BLAKE3,
    )
    .expect("witness_generator_native must succeed for embedded blake3 + canned input");
    std::io::stdout()
        .write_all(&witness_bytes)
        .expect("stdout write of dumped witness bytes must succeed");
}
