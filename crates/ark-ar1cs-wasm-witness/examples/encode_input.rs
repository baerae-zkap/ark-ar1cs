//! Emit a hex-encoded `postcard` blob for `LargeMockInput { seed, depth }`.
//!
//! The wasm-witness ABI consumes postcard-encoded input bytes. Node has no
//! postcard implementation, so we generate the bytes here (single source
//! of truth) and pipe the hex into the Node bench harness.
//!
//! Run via:
//! ```bash
//! cargo run --release -p ark-ar1cs-wasm-witness \
//!   --features test-mock --example encode_input -- 20
//! ```
//!
//! Argv `[depth]` defaults to 20. `seed` is fixed at 3 — keeps measurement
//! determinism. Stdout is the hex blob, stderr is metadata.

use ark_ar1cs_wasm_witness::mock::{LargeMockInput, EMBEDDED_LARGE_AR1CS_BLAKE3};

fn main() {
    let depth: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let input = LargeMockInput { seed: 3, depth };
    let bytes = postcard::to_allocvec(&input).expect("postcard encode failed");

    eprintln!(
        "input={{seed:3, depth:{depth}}}  postcard_bytes={}  embedded_blake3={}",
        bytes.len(),
        hex_encode(&EMBEDDED_LARGE_AR1CS_BLAKE3),
    );
    println!("{}", hex_encode(&bytes));
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
