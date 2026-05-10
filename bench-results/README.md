# bench-results/

Raw measurement output from the 2^20 wasm-witness benchmark plan
(`.omc/plans/2026-05-07-wasm-witness-2pow20-benchmark.md`).

Files:

- `01-native-baseline.json` — `examples/native_mem_2pow20` output + criterion summary
- `01-synthesis-mode-delta.md` — peak-heap & wall-time before/after the
  `Prove { construct_matrices: false }` switch
- `03-node-v8.json` — Node.js / V8 wasm runtime measurements
- `03-decision-gate.md` — Phase 3 G3 gate evaluation
- `04-ios-hermes.json`, `04-ios-wkwebview.json`, `04-android-*.json` —
  device measurements (Phase 4)

Raw `*.json` and `*.txt` are gitignored — only this README is tracked.
Summaries that survive go in `docs/benchmarks-2pow20.md`.

Host metadata MUST be embedded in every JSON output (chip model, OS
version, RAM, RN version where applicable) — measurements are not
comparable across environments otherwise.
