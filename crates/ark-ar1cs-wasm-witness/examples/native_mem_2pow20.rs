//! Native heap profile for `circuit_to_arwtns` at depth 20.
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

use ark_ar1cs_format::CurveId;
use ark_ar1cs_wasm_witness::{
    circuit_to_arwtns,
    mock::{LargeMockCircuit, EMBEDDED_LARGE_AR1CS_BLAKE3},
};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Picks the constraint-system synthesis mode. Set via env var
/// `WITNESS_MODE`:
///
/// - unset / `witness_only` (default): the production path —
///   `Prove { construct_matrices: false }`. Output goes through
///   `circuit_to_arwtns`.
/// - `prove_full`: the historical default — `Prove { construct_matrices: true }`.
///   Open-codes the same extraction `circuit_to_arwtns` does so the heap
///   accounting is comparable. Used to quantify the SynthesisMode
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
    let arwtns: ArwtnsFile<Fr> = if mode == "prove_full" {
        // Open-coded equivalent of circuit_to_arwtns but with
        // `construct_matrices: true` — the pre-optimization path.
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        circuit
            .generate_constraints(cs.clone())
            .expect("generate_constraints failed");
        let inner = cs.borrow().expect("cs borrow failed");
        let instance: Vec<Fr> = inner.instance_assignment[1..].to_vec();
        let witness: Vec<Fr> = inner.witness_assignment.clone();
        drop(inner);
        ArwtnsFile::from_assignments(
            CurveId::Bn254,
            EMBEDDED_LARGE_AR1CS_BLAKE3,
            &instance,
            &witness,
        )
    } else {
        circuit_to_arwtns(circuit, CurveId::Bn254, EMBEDDED_LARGE_AR1CS_BLAKE3)
            .expect("circuit_to_arwtns failed")
    };
    let elapsed = t0.elapsed();

    // Compute serialized .arwtns size — relevant for the wasm-host bridge
    // transfer cost analysis later.
    let arwtns_size_bytes = {
        let mut buf = Vec::new();
        arwtns.write(&mut buf).expect("arwtns write failed");
        buf.len()
    };

    let stats = dhat::HeapStats::get();

    // Single JSON line on stdout — easy to pipe into a results file.
    let report = format!(
        "{{\"circuit\":\"large-mock-2pow20-v0\",\
        \"mode\":\"{mode}\",\
        \"depth\":{depth},\
        \"constraints\":{constraints},\
        \"witness_count\":{witness},\
        \"instance_count\":{instance},\
        \"arwtns_byte_size\":{arwtns_size},\
        \"wall_time_ms\":{wall_ms},\
        \"peak_heap_bytes\":{peak},\
        \"total_alloc_bytes\":{total},\
        \"alloc_count\":{count},\
        \"fr_compressed_size\":32}}",
        mode = mode,
        depth = depth,
        constraints = 1u64 << depth,
        witness = arwtns.witness.len(),
        instance = arwtns.instance.len(),
        arwtns_size = arwtns_size_bytes,
        wall_ms = elapsed.as_millis(),
        peak = stats.max_bytes,
        total = stats.total_bytes,
        count = stats.total_blocks,
    );
    // BN254 Fr is 32 bytes compressed — hardcoded above to avoid pulling
    // ark-serialize as an explicit dep.
    println!("{report}");
}
