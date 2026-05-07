# 2^20 Wasm-Witness Benchmark — Phase 1–3 Summary

**Plan:** [`.omc/plans/2026-05-07-wasm-witness-2pow20-benchmark.md`](../.omc/plans/2026-05-07-wasm-witness-2pow20-benchmark.md)
**Branch:** `feat/arzkey-v1-envelope-support`
**Date:** 2026-05-07
**Status:** Phases 1–3 complete · Phase 4 (mobile) deferred to user-driven device session.

---

## Reference circuit — what was measured

`LargeMockCircuit` (`crates/ark-ar1cs-wasm-witness/src/mock.rs:124-176`).

A synthetic chained-squaring circuit:

```
x_0 = seed
x_{i+1} = x_i^2   for i in 0 .. 2^20-1   (each step = 1 R1CS constraint)
public input: x_{2^20}
```

- Field: BN254 Fr (32 B)
- Constraints: **2^20 = 1,048,576**
- Witness variables: 2^20 (`x_0 … x_{2^20 − 1}`)
- Public input variables: 1 (`x_{2^20}`)

Not a real application circuit — picked because it exercises arkworks' `ConstraintSynthesizer` machinery and BN254 field multiplication at the right scale (anon-aadhaar tier ≈ 1M constraints) while having no hash/RSA gadget noise. The wasm runtime overhead the test measures is generic to any BN254 R1CS circuit.

Input encoding: `LargeMockInput { seed: u64, depth: u32 }` → postcard varint, 2 bytes for `(seed=3, depth=20)`.

Output: `.arwtns` file format (see `crates/ark-ar1cs-wtns/`), 33,554,560 bytes (= 2^20 × 32 + ~192 B header).

---

## Host

| Field | Value |
|---|---|
| Chip | Apple M4 Pro |
| OS | macOS 15.7.4 (build 24G517) |
| RAM | 24 GB |
| rustc | 1.93.1 (01f6ddf75 2026-02-11) |
| Node.js | v20.20.2 |
| V8 | 11.3.244.8-node.38 |

---

## Headline numbers

| Path | Wall time (median) | Peak heap / RSS | Notes |
|---|---|---|---|
| **Native** (criterion) | **69.8 ms** | 144 MiB (dhat) | floor; Prove { construct_matrices: false } |
| **Native legacy** | n/a | 455 MiB (dhat) | Prove { construct_matrices: true } — pre-optimization |
| **Node V8 wasm warm** | **122.7 ms** | 444 MB (Node RSS) | 1.76× native, σ very tight (122–123 ms) |
| **Node V8 wasm first call** | 167 ms | — | cold tier (Liftoff) before TurboFan |
| **Node compile + instantiate** | 2.81 ms | — | 61 KB wasm module |

Wasm overhead vs native: **1.76×** (V8 TurboFan).
arwtns output is byte-identical (sha256 `5be08c6c…109341b`) across native and wasm paths.

---

## Decision gates (plan §6)

| Gate | Threshold | Measured | Result |
|---|---|---|---|
| **G1** SynthesisMode peak heap savings | ≥ 50 MB | **−311 MB** | ✅ PASS by 6.2× |
| **G2** native floor | < 5 s, < 1 GB | 69.8 ms / 144 MiB | ✅ PASS by 71×, 7× |
| **G3** Node V8 wasm warm | ≤ 3 × native, RSS ≤ 2 GB | 1.76× / 0.44 GB | ✅ PASS by 1.7×, 4.5× |
| **G4** byte-identity native↔wasm | bytewise equal | sha256 match | ✅ PASS |

All gates pass. **Phase 4 (mobile measurements) entry approved.**

---

## Pre-measurement vs measured (claim audit)

Codex flagged three of my pre-plan claims as "assumptions, not facts." Hard data now in:

| Claim | Pre-measure | Measured | Verdict |
|---|---|---|---|
| ~256 MB intermediate memory | speculative | **144 MiB** peak | over-estimated by 1.8× |
| iOS Hermes 5–15 s at 2^20 | extrapolation | (Phase 4); projection now **0.7–1.5 s** based on 70 ms native floor | over-estimated by 5–20× |
| WKWebView trampoline 1–3 s | speculative | (Phase 4) — TBD | TBD |

Native floor (70 ms) was 10–100× faster than my pre-measurement estimate of 1–2 s. This collapses every downstream projection by the same factor: Hermes interpreter at 10–20× slowdown over JIT now projects to **0.7–1.5 s on iOS**, not 5–15 s. The simpler "Hermes-only" path becomes plausible.

---

## SynthesisMode optimization (commit `a530b40`)

The pre-measurement code change codex called "highest-value":

`crates/ark-ar1cs-wasm-witness/src/lib.rs:95` flipped from default
`Prove { construct_matrices: true }` to `Prove { construct_matrices: false }`.

Effect on 2^20:
- Peak heap: 455 MiB → **144 MiB** (−311 MB / −68%)
- Total alloc bytes: 751 MiB → 512 MiB (−239 MB)
- Alloc count: 3.67M → 3.15M (−524k)
- arwtns output: byte-identical (no behavioral change)

The savings come from skipping `enforce_constraint`'s `a_constraints`/`b_constraints`/`c_constraints` Vec accumulation and the associated `lc_map` BTreeMap, which the wasm-witness path never reads (the prover loads matrices from `.arzkey` instead).

Detail: [`01-synthesis-mode-delta.md`](01-synthesis-mode-delta.md).

---

## What changed in the codebase

| Commit | Subject | Lines |
|---|---|---|
| `a530b40` | perf(wasm-witness): skip A/B/C row accumulation in circuit_to_arwtns | +59 −7 |
| `91f4068` | feat(wasm-witness): add mock module with MockCircuit + LargeMockCircuit (2^20) | +289 −27 |
| `c6abe27` | feat(wasm-witness): add large-witness-fixture cdylib (2^20 chained-square) | +97 |
| `ca004e9` | bench(wasm-witness): native baseline at 2^20 + SynthesisMode delta | +816 −3 |
| `561fd84` | bench(wasm-witness): Node V8 wasm baseline at 2^20 — G3/G4 PASS | +446 |

Architectural surface unchanged: `prove(arzkey, arwtns)` signature is invariant (`crates/ark-ar1cs-prover/src/lib.rs:43-74`), `WitnessGenerator` trait shape is invariant, `.arwtns` byte format is invariant.

---

## What's not yet measured (Phase 4)

User-driven, requires external resources:

1. **iOS Hermes wasm** (RN 0.84+, interpreter tier)
2. **iOS WKWebView trampoline** (JSC JIT, postMessage ArrayBuffer transfer)
3. **Android Hermes wasm** (interpreter)
4. **Android react-native-webview wasm** (V8/JSC JIT)

Resources needed: Apple Developer account, iOS device (iPhone 13+ recommended), Android dev device, Xcode + Android Studio + RN 0.84+ environment.

The Phase 3 G3 PASS justifies this investment — the path is not blocked by anything visible in the Node measurement.

---

## Reproduction

```bash
# Sanity tests
cargo test -p ark-ar1cs-wasm-witness --release          # 22 pass

# Native
cargo bench -p ark-ar1cs-wasm-witness --features test-mock --bench native_2pow20
WITNESS_MODE=witness_only cargo run --release -p ark-ar1cs-wasm-witness \
  --features test-mock --example native_mem_2pow20
WITNESS_MODE=prove_full   cargo run --release -p ark-ar1cs-wasm-witness \
  --features test-mock --example native_mem_2pow20

# Wasm fixture
cargo build -p large-witness-fixture --target wasm32-unknown-unknown --release

# Node V8 wasm
INPUT=$(cargo run --release -p ark-ar1cs-wasm-witness --features test-mock \
  --example encode_input --quiet -- 20)
cd bench-harness/node
node --expose-gc --max-old-space-size=4096 run-bench.mjs \
  --wasm ../../target/wasm32-unknown-unknown/release/large_witness_fixture.wasm \
  --input "$INPUT" --iterations 10 --warmup 2 \
  --out ../../bench-results/03-node-v8.json
```

Raw outputs land in `bench-results/*.json` (gitignored). Summaries (this file, `01-synthesis-mode-delta.md`, `03-decision-gate.md`) are tracked.
