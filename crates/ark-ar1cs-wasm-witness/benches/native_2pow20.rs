//! Native baseline for the 2^20-constraint witness generation path.
//!
//! Run via:
//! ```bash
//! cargo bench -p ark-ar1cs-wasm-witness --features test-mock --bench native_2pow20
//! ```
//!
//! Each iteration synthesizes ~1M BN254 squarings → ~1 s at 1 µs/op on a
//! modern Apple silicon. We deliberately drop criterion's default sample
//! count and measurement time so the bench finishes in a couple of minutes
//! instead of 30+. The numbers feed `bench-results/01-native-baseline.json`.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_ar1cs_wasm_witness::{mock::LargeMockCircuit, synthesize_full_assignment};
use ark_bn254::Fr;

fn bench_native_synthesize_full_assignment_2pow20(c: &mut Criterion) {
    let mut group = c.benchmark_group("native_synthesize_full_assignment_2pow20");
    // 2^20 squarings is heavy; cap the sample set so total wall time is
    // bounded. p99 is noisier with 10 samples — that's the trade.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(5));

    group.bench_function("depth_20", |b| {
        b.iter(|| {
            let circuit = LargeMockCircuit {
                seed: black_box(Fr::from(3u64)),
                depth: black_box(20),
            };
            let full = synthesize_full_assignment::<_, Fr>(circuit)
                .expect("native synthesize_full_assignment failed");
            black_box(full);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_native_synthesize_full_assignment_2pow20);
criterion_main!(benches);
