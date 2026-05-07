#!/usr/bin/env node
// Node.js / V8 wasm bench harness for `large_witness_fixture.wasm`.
//
// Usage:
//   node --expose-gc --max-old-space-size=4096 run-bench.mjs \
//     --wasm <path-to-.wasm> --input <hex> [--iterations N] [--warmup N] \
//     [--out <result.json>]
//
// All numbers go to stdout as a single JSON line at the end. Per-call
// detail (cold vs warm) is on stderr for live observation.
//
// Notes:
//   * `--expose-gc` lets us trigger GC between cold and warm phases so the
//     peak RSS reading is less noisy.
//   * `--max-old-space-size=4096` is well above the wasm linear-memory
//     ceiling but below the system's 24 GB so we don't accidentally hide
//     memory pressure.
//   * postcard input must be hex-encoded by `examples/encode_input.rs`
//     (single source of truth — Node has no postcard impl).

import fs from 'node:fs/promises';
import os from 'node:os';
import process from 'node:process';

const BLAKE3_LEN = 32;
const PTR_PAIR_LEN = 8; // out_ptr_out (u32) + out_len_out (u32)

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------
function argval(flag, fallback) {
  const i = process.argv.indexOf(flag);
  if (i === -1) return fallback;
  return process.argv[i + 1];
}

const wasmPath = argval('--wasm');
const inputHex = argval('--input');
const iterations = Number(argval('--iterations', '10'));
const warmup = Number(argval('--warmup', '2'));
const outFile = argval('--out');
const dumpArwtns = argval('--dump-arwtns');

if (!wasmPath || !inputHex) {
  console.error('usage: run-bench.mjs --wasm <path> --input <hex> [--iterations N] [--warmup N] [--out <result.json>]');
  process.exit(2);
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s/g, '');
  if (clean.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

const inputBytes = hexToBytes(inputHex);

// ---------------------------------------------------------------------------
// Memory polling: 10 ms cadence, max RSS captured.
// ---------------------------------------------------------------------------
class RssTracker {
  constructor() {
    this.maxRss = 0;
    this.maxHeapUsed = 0;
    this.timer = null;
  }
  start() {
    this.timer = setInterval(() => this.sample(), 10);
  }
  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.sample();
  }
  sample() {
    const m = process.memoryUsage();
    if (m.rss > this.maxRss) this.maxRss = m.rss;
    if (m.heapUsed > this.maxHeapUsed) this.maxHeapUsed = m.heapUsed;
  }
}

// ---------------------------------------------------------------------------
// Wasm runner
// ---------------------------------------------------------------------------
class WasmRunner {
  constructor(exports, memory) {
    this.exports = exports;
    this.memory = memory;
  }
  static async load(bytes) {
    const t0 = process.hrtime.bigint();
    const module = await WebAssembly.compile(bytes);
    const t1 = process.hrtime.bigint();
    const instance = await WebAssembly.instantiate(module, {});
    const t2 = process.hrtime.bigint();
    return {
      runner: new WasmRunner(instance.exports, instance.exports.memory),
      compileMs: Number(t1 - t0) / 1e6,
      instantiateMs: Number(t2 - t1) / 1e6,
    };
  }
  view() { return new Uint8Array(this.memory.buffer); }
  dv()   { return new DataView(this.memory.buffer); }

  // Read embedded blake3 (and free the wasm-side buffer).
  readEmbeddedBlake3() {
    const slots = this.exports.wasm_alloc(PTR_PAIR_LEN);
    const code = this.exports.embedded_ar1cs_blake3(slots, slots + 4);
    if (code !== 0) throw new Error(`embedded_ar1cs_blake3 returned ${code}`);
    const dv = this.dv();
    const ptr = dv.getUint32(slots, true);
    const len = dv.getUint32(slots + 4, true);
    if (len !== BLAKE3_LEN) throw new Error(`unexpected blake3 len ${len}`);
    const out = new Uint8Array(this.memory.buffer.slice(ptr, ptr + len));
    this.exports.wasm_free(ptr, len);
    this.exports.wasm_free(slots, PTR_PAIR_LEN);
    return out;
  }

  // Run witness_generator. Returns { code, arwtnsBytes, callMs }.
  callWitnessGenerator(input, hostBlake3) {
    const inputPtr = this.exports.wasm_alloc(input.length);
    this.view().set(input, inputPtr);

    const blakePtr = this.exports.wasm_alloc(BLAKE3_LEN);
    this.view().set(hostBlake3, blakePtr);

    const slots = this.exports.wasm_alloc(PTR_PAIR_LEN);

    const t0 = process.hrtime.bigint();
    const code = this.exports.witness_generator(
      inputPtr, input.length, blakePtr, slots, slots + 4,
    );
    const t1 = process.hrtime.bigint();

    let arwtnsBytes = null;
    if (code === 0) {
      const dv = this.dv();
      const outPtr = dv.getUint32(slots, true);
      const outLen = dv.getUint32(slots + 4, true);
      arwtnsBytes = new Uint8Array(this.memory.buffer.slice(outPtr, outPtr + outLen));
      this.exports.wasm_free(outPtr, outLen);
    }
    this.exports.wasm_free(inputPtr, input.length);
    this.exports.wasm_free(blakePtr, BLAKE3_LEN);
    this.exports.wasm_free(slots, PTR_PAIR_LEN);

    return { code, arwtnsBytes, callMs: Number(t1 - t0) / 1e6 };
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function main() {
  const wasmBytes = await fs.readFile(wasmPath);
  const wasmSize = wasmBytes.length;

  if (typeof globalThis.gc === 'function') globalThis.gc();
  const tracker = new RssTracker();
  tracker.start();

  // Cold load + instantiate.
  const tLoad0 = process.hrtime.bigint();
  const { runner, compileMs, instantiateMs } = await WasmRunner.load(wasmBytes);
  const tLoad1 = process.hrtime.bigint();
  const totalLoadMs = Number(tLoad1 - tLoad0) / 1e6;

  // Embedded blake3 (also checks the export wiring works).
  const embeddedBlake3 = runner.readEmbeddedBlake3();
  console.error(`embedded_ar1cs_blake3 = ${bytesToHex(embeddedBlake3)}`);

  // First call (cold path within the instance).
  const first = runner.callWitnessGenerator(inputBytes, embeddedBlake3);
  if (first.code !== 0) {
    throw new Error(`witness_generator (first) failed code=${first.code}`);
  }
  console.error(`first call: ${first.callMs.toFixed(2)} ms (arwtns ${first.arwtnsBytes.length} B)`);

  if (dumpArwtns) {
    await fs.writeFile(dumpArwtns, first.arwtnsBytes);
    console.error(`dumped wasm arwtns bytes to ${dumpArwtns}`);
  }

  // Warmup.
  for (let i = 0; i < warmup; i++) {
    const r = runner.callWitnessGenerator(inputBytes, embeddedBlake3);
    if (r.code !== 0) throw new Error(`warmup ${i} failed code=${r.code}`);
    console.error(`warmup ${i}: ${r.callMs.toFixed(2)} ms`);
  }

  // Measured warm calls.
  const warmCallsMs = [];
  for (let i = 0; i < iterations; i++) {
    const r = runner.callWitnessGenerator(inputBytes, embeddedBlake3);
    if (r.code !== 0) throw new Error(`warm iteration ${i} failed code=${r.code}`);
    warmCallsMs.push(r.callMs);
    console.error(`warm ${i}: ${r.callMs.toFixed(2)} ms`);
  }

  tracker.stop();

  warmCallsMs.sort((a, b) => a - b);
  const stat = arr => ({
    mean:   arr.reduce((a, b) => a + b, 0) / arr.length,
    median: arr[Math.floor(arr.length / 2)],
    p99:    arr[Math.min(arr.length - 1, Math.floor(arr.length * 0.99))],
    min:    arr[0],
    max:    arr[arr.length - 1],
  });

  const result = {
    plan_id: '2026-05-07-wasm-witness-2pow20-benchmark',
    phase: 'Phase 3 (Node V8 wasm)',
    host: {
      runtime: `node-${process.version}`,
      engine: 'v8',
      v8_version: process.versions.v8,
      os: `${os.type()} ${os.release()}`,
      arch: process.arch,
      cpus: os.cpus()[0]?.model,
      ram_gb: Math.round(os.totalmem() / 1024 / 1024 / 1024),
      flags: process.execArgv,
    },
    wasm: {
      path: wasmPath,
      size_bytes: wasmSize,
      embedded_blake3_hex: bytesToHex(embeddedBlake3),
    },
    input: {
      hex: inputHex,
      bytes: inputBytes.length,
    },
    instantiate: {
      compile_ms: compileMs,
      instantiate_ms: instantiateMs,
      total_load_ms: totalLoadMs,
    },
    first_call_ms: first.callMs,
    warm_calls_ms: warmCallsMs,
    warm_stats_ms: stat(warmCallsMs),
    arwtns_byte_size: first.arwtnsBytes.length,
    arwtns_first_16_bytes_hex: bytesToHex(first.arwtnsBytes.slice(0, 16)),
    peak: {
      rss_bytes: tracker.maxRss,
      heap_used_bytes: tracker.maxHeapUsed,
    },
    iterations,
    warmup,
  };

  const json = JSON.stringify(result, null, 2);
  if (outFile) {
    await fs.writeFile(outFile, json);
    console.error(`wrote ${outFile}`);
  } else {
    console.log(json);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
