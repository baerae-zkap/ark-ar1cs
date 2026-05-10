# Phase 3 Decision Gate — Node V8 wasm

**Plan:** `.omc/plans/2026-05-07-wasm-witness-2pow20-benchmark.md`
**Phase:** 3 (Node V8 wasm baseline)
**Date:** 2026-05-07
**Result:** ✅ **GATE PASS — Phase 4 (mobile) entry approved**

---

## Measurement summary

Apple M4 Pro · macOS 15.7.4 · Node v20.20.2 · V8 11.3.244.8 · 24 GB RAM
Wasm: `large_witness_fixture.wasm` (61 KB) · `LargeMockInput { seed: 3, depth: 20 }` (postcard 2 B)

| Metric | Native (criterion) | Node V8 wasm | Wasm overhead |
|---|---|---|---|
| Wall time, median | **69.8 ms** | **122.7 ms** | **1.76x** |
| Wall time, p99 | 70.4 ms | 123.1 ms | 1.75x |
| First call (cold-tier) | n/a | 167 ms | — |
| Cold compile + instantiate | n/a | 2.81 ms | — |
| `.arwtns` output bytes | 33,554,560 | 33,554,560 | byte-identical (sha256 `5be08c6c…109341b`) |
| Peak heap / RSS | 144 MiB (dhat) | 444.9 MB (Node RSS, includes V8 baseline) | — |

Warm samples (10): 122.06, 122.26, 122.27, 122.50, 122.52, 122.66, 122.67, 123.05, 123.06, 123.11 ms — extremely tight σ.

## Gates (plan §6)

| Gate | Threshold | Measured | Result |
|---|---|---|---|
| **G3 warm time** | warm ≤ 3 × native | 1.76 × native | ✅ PASS (margin 1.7x under) |
| **G3 RSS** | ≤ 2 GB | 0.44 GB | ✅ PASS (margin 4.5x under) |
| **G4 byte-identity** | wasm == native bytewise | sha256 match | ✅ PASS |
| arwtns size sanity | ~33 MB (= 2^20 × 32 + header) | 33,554,560 B | ✅ PASS |

All G3/G4 criteria satisfied. **No fail conditions hit** (none of "cold > 10s", "warm > 7s", "RSS > 2 GB", "RSS > 4 GB", "arwtns > 100 MB").

## What this means for mobile

Node V8 wasm runs at **~76% of native speed** for arkworks BN254 arithmetic at 2^20. V8's TurboFan tier-up does most of the closing of the gap.

Implications for Phase 4 path predictions (rough scaling):

| Path | Predicted warm time | Confidence |
|---|---|---|
| Android Chrome / WebView (V8 JIT) | ~120-200 ms | High (same engine as Node) |
| iOS WKWebView (JSC JIT) | 150-300 ms | Medium (JSC slower for arithmetic per Wasmer 2023 benchmark) |
| iOS Hermes v1 wasm (interpreter) | **0.7–1.5 s** | Medium (10-20x interpreter penalty over JIT) |
| Android wasm3 / wasmi (interpreter) | 0.7–1.5 s | Medium |

Pre-measurement, I had projected iOS Hermes at 5–15 s. **Actual native floor (70 ms vs my 1-2 s estimate) means the interpreter projection drops 10x.** Hermes-only on iOS now looks viable, not just WKWebView trampoline.

## Pre-measurement vs measured (claim audit)

Codex flagged three of my claims as "assumptions, not architecture facts":

| Claim | Pre-measurement | Measured | Verdict |
|---|---|---|---|
| WKWebView trampoline 1–3 s | speculative | not yet measured (Phase 4) | TBD |
| ~256 MB intermediate memory | speculative | **144 MiB** (witness_only) | over-estimated by 1.8x |
| iOS Hermes 5–15 s | extrapolation | (not yet measured); projection now 0.7–1.5 s | over-estimated by 5–20x |

The pre-measurement narrative consistently overshot. Codex's "measure before sell" critique is now backed by hard data.

## Decision

**Proceed to Phase 4** with the four mobile measurement modes (iOS Hermes, iOS WKWebView, Android Hermes, Android WebView) as defined in plan §4.2.

If Phase 4 confirms iOS Hermes at < 3 s warm, the simpler "Hermes only" path becomes the default (skip WKWebView trampoline complexity). If Hermes overshoots, fall back to WKWebView per plan §6 G6.

## Reproduction

```bash
# Native baseline
cargo bench -p ark-ar1cs-wasm-witness --features test-mock --bench native_2pow20

# Wasm fixture build
cargo build -p large-witness-fixture --target wasm32-unknown-unknown --release

# Postcard input (seed=3, depth=20)
INPUT=$(cargo run --release -p ark-ar1cs-wasm-witness --features test-mock --example encode_input --quiet -- 20)

# Node V8 bench
cd bench-harness/node
node --expose-gc --max-old-space-size=4096 run-bench.mjs \
  --wasm ../../target/wasm32-unknown-unknown/release/large_witness_fixture.wasm \
  --input "$INPUT" --iterations 10 --warmup 2 \
  --out ../../bench-results/03-node-v8.json

# G4 byte-identity
cargo run --release -p ark-ar1cs-wasm-witness --features test-mock \
  --example native_dump_arwtns --quiet -- 20 > /tmp/native.bin
node --expose-gc run-bench.mjs --wasm <wasm> --input "$INPUT" --iterations 1 --warmup 0 \
  --dump-arwtns /tmp/wasm.bin
cmp /tmp/native.bin /tmp/wasm.bin && echo OK
```
