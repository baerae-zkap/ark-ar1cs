//! Native heap profile for `synthesize_full_assignment` at depth 20.
//!
//! Run via:
//! ```bash
//! cargo run --release -p ark-ar1cs-wasm-witness \
//!   --features test-mock --example native_mem_2pow20
//! ```
//!
//! Uses [`dhat`] as the global allocator. Prints peak heap usage and total
//! bytes allocated as a single JSON line on stdout for easy ingestion into
//! `bench-results/01-native-baseline.json`. Also writes a full
//! `dhat-heap.json` next to the binary (drop side-effect of `Profiler`)
//! for retrospective inspection.

use std::time::Instant;

use ark_ar1cs_wasm_witness::{mock::LargeMockCircuit, synthesize_full_assignment};
use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Picks the constraint-system synthesis mode. Set via env var
/// `WITNESS_MODE`:
///
/// - unset / `witness_only` (default): the production path —
///   `Prove { construct_matrices: false }`. Output goes through
///   `synthesize_full_assignment`.
/// - `prove_full`: the historical default — `Prove { construct_matrices: true }`.
///   Open-codes the same extraction `synthesize_full_assignment` does so the
///   heap accounting is comparable. Used to quantify the SynthesisMode
///   optimization (commit a530b40).
fn pick_mode() -> &'static str {
    match std::env::var("WITNESS_MODE")
        .unwrap_or_else(|_| "witness_only".to_string())
        .as_str()
    {
        "prove_full" => "prove_full",
        _ => "witness_only",
    }
}

fn main() {
    let depth: u32 = 20;
    let mode = pick_mode();

    let _profiler = dhat::Profiler::new_heap();

    let t0 = Instant::now();
    let circuit = LargeMockCircuit {
        seed: Fr::from(3u64),
        depth,
    };
    let full_assignment: Vec<Fr> = if mode == "prove_full" {
        // Open-coded equivalent of synthesize_full_assignment but with
        // `construct_matrices: true` — the pre-optimization path.
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });
        circuit
            .generate_constraints(cs.clone())
            .expect("generate_constraints failed");
        let inner = cs.borrow().expect("cs borrow failed");
        let mut full: Vec<Fr> = Vec::with_capacity(
            inner.assignments.instance_assignment.len()
                + inner.assignments.witness_assignment.len(),
        );
        full.push(Fr::ONE);
        full.extend_from_slice(&inner.assignments.instance_assignment[1..]);
        full.extend_from_slice(&inner.assignments.witness_assignment);
        drop(inner);
        full
    } else {
        synthesize_full_assignment::<_, Fr>(circuit).expect("synthesize_full_assignment failed")
    };
    let elapsed = t0.elapsed();

    // Compute serialized full-assignment size (Vec<F> ark-serialize compressed) —
    // relevant for the wasm-host bridge transfer cost analysis later.
    let witness_size_bytes = {
        let mut buf = Vec::new();
        full_assignment
            .serialize_compressed(&mut buf)
            .expect("full assignment serialize failed");
        buf.len()
    };

    let stats = dhat::HeapStats::get();

    // Counts: the full assignment is `[F::ONE, instance..., witness...]`,
    // so subtract 1 for the prepended ONE wire and 1 more for the leading
    // single instance variable of LargeMockCircuit.
    let total_len = full_assignment.len();
    let instance_count = 1usize; // LargeMockCircuit declares exactly one public input.
    let witness_count = total_len - 1 - instance_count;

    // Single JSON line on stdout — easy to pipe into a results file.
    let report = format!(
        "{{\"circuit\":\"large-mock-2pow20-v0\",\
        \"mode\":\"{mode}\",\
        \"depth\":{depth},\
        \"constraints\":{constraints},\
        \"witness_count\":{witness},\
        \"instance_count\":{instance},\
        \"witness_byte_size\":{witness_size},\
        \"wall_time_ms\":{wall_ms},\
        \"peak_heap_bytes\":{peak},\
        \"total_alloc_bytes\":{total},\
        \"alloc_count\":{count},\
        \"fr_compressed_size\":32}}",
        mode = mode,
        depth = depth,
        constraints = 1u64 << depth,
        witness = witness_count,
        instance = instance_count,
        witness_size = witness_size_bytes,
        wall_ms = elapsed.as_millis(),
        peak = stats.max_bytes,
        total = stats.total_bytes,
        count = stats.total_blocks,
    );
    // BN254 Fr is 32 bytes compressed — hardcoded above for symmetry with
    // the pre-refactor report shape.
    println!("{report}");
}
