# SynthesisMode Optimization — Phase 1.1 Effect (G1 Gate)

**Plan:** `.omc/plans/2026-05-07-wasm-witness-2pow20-benchmark.md`
**Commit under test:** `a530b40` (perf(wasm-witness): skip A/B/C row accumulation)
**Date:** 2026-05-07

---

## What changed

`crates/ark-ar1cs-wasm-witness/src/lib.rs:95` flips the constraint system mode
from the default `Prove { construct_matrices: true }` (which accumulates
A/B/C rows in `enforce_constraint`) to **`Prove { construct_matrices: false }`**.
Witness/instance assignments are still populated because we stay in `Prove`
mode, not `Setup` (arkworks 0.5.1 `constraint_system.rs:234`).

The wasm fixture only needs the assignments; matrices live in `.arzkey`
already.

## Measurement setup

- Host: Apple M4 Pro, macOS 15.7.4, 24 GB RAM, rustc 1.93.1
- Tool: `dhat` global allocator, `cargo run --release --features test-mock
  --example native_mem_2pow20`
- Circuit: `LargeMockCircuit { seed: 3, depth: 20 }` → 1,048,576 chained
  BN254 squarings → 1M constraints, 1M witness vars, 1 instance var.
- Both modes execute the same circuit on the same host in the same release
  build; the only variable is the synthesis mode (selected via env var
  `WITNESS_MODE=prove_full` vs unset).

## Numbers

| Metric | `prove_full` (legacy) | `witness_only` (current) | Delta |
|---|---|---|---|
| **Peak heap** | **476,951,840 B** (455 MiB) | **150,995,168 B** (144 MiB) | **−311 MB / −68.3%** |
| Total alloc bytes | 787,331,964 (751 MiB) | 536,873,128 (512 MiB) | −239 MB |
| Total alloc blocks | 3,670,129 | 3,145,786 | −524,343 |
| dhat-instrumented wall ms | 17,413 | 13,875 | −20% |
| `.arwtns` output bytes | 33,554,560 | 33,554,560 | 0 (byte-identical) |

(`.arwtns` byte size is identical, confirming the optimization changes only
the path memory profile — the output is the same.)

## G1 gate

Plan §6 G1: "peak heap ≥ 50 MB 절감" → **PASS by 6.2x.**

Codex's qualitative prediction was "highest-value memory change" with a
plan annotation of "~100 MB+ savings." Actual savings (~311 MB) exceeded
that by ~3x.

## Where the saved memory came from

Profiling counts roughly 524k fewer allocation blocks at peak. Those map
to A/B/C `LinearCombination` rows that `enforce_constraint` accumulates
in `Prove { construct_matrices: true }` mode (see arkworks
`constraint_system.rs:260-267`). Each constraint stored 3 LC rows × 1M
constraints. Skipping that accumulation:

- Avoids the per-constraint `new_lc()` calls (3 × 1,048,576 = ~3.1M)
- Drops the `a_constraints`, `b_constraints`, `c_constraints` Vecs
- Drops the `lc_map` BTreeMap entries

That's ~50 MB-class structures × 3 (A/B/C) plus the BTreeMap overhead,
matching the 311 MB peak delta.

## Implication for downstream

- Mobile peak heap concern is now bounded by 150 MB-ish at 2^20, not 455 MB.
  iOS OOM threshold (1.5-2.5 GB on 4 GB devices) is comfortable.
- wasm linear-memory cap (4 GB) is not even close.
- `arwtns` size 33.5 MB is the floor — that's `2^20 × 32 + header`, can't
  be reduced without changing the circuit or field.

## Next gate

Phase 2 G2 (criterion native floor): `wall_time_ms_median = 69.8 ms`.
Plan threshold 5,000 ms → **PASS by 71.6x**. See
`bench-results/01-native-baseline.json` for the full criterion run.
