# ark-ar1cs

A portable Groth16 toolkit for [arkworks](https://github.com/arkworks-rs)
circuits. Serialize a finalized constraint system, the Groth16 setup output
(PK + VK), and a witness assignment to a fixed byte format, then prove and
verify directly from the artifacts — no original `ConstraintSynthesizer`
needed at prove time.

## Why

Standard arkworks Groth16 keeps the original Rust circuit in memory through
trusted setup, witness generation, and prove. That couples deployment to
the circuit code. ark-ar1cs cuts the coupling: every step after
`cs.finalize()` works from bytes alone. This unlocks:

- Sending setup output to a verifier on a different host.
- Running `prove` on a machine that doesn't know the circuit definition.
- Auditing a frozen constraint system.
- Handing a witness from one component to another (e.g. wasm witness
  generator → Rust prover).

## Project surface

The project surface is **three crates** producing **two artifact
formats**, split along the runtime / build-time axis.

```text
crates/
├── ark-ar1cs/                  ← R (runtime) — codec read paths + prove/verify
├── ark-ar1cs-build/            ← B (build-time) — Circuit → .ar1cs + .arzkey
└── ark-ar1cs-wasm-witness/     ← Circuit → circuit.wasm witness generator
```

| Crate | Role | Artifacts |
|-------|------|-----------|
| [`ark-ar1cs`](crates/ark-ar1cs)                           | **R** — runtime codecs + `prove`/`verify`. `format::importer`, `arzkey::ArzkeyFile::read`, prove path. Wasm-clean. | reads `.ar1cs`, `.arzkey` |
| [`ark-ar1cs-build`](crates/ark-ar1cs-build)               | **B** — build-time toolchain. `export_circuit` (Circuit → `.ar1cs`) and `from_setup_output` (matrices + PK → `.arzkey`). Native-only. | writes `.ar1cs`, `.arzkey` |
| [`ark-ar1cs-wasm-witness`](crates/ark-ar1cs-wasm-witness) | Macro-driven `circuit.wasm` witness generator. | writes raw `Vec<F>` witness via `ark-serialize` |

Runnable end-to-end workflows live in
[`crates/ark-ar1cs/examples/`](crates/ark-ar1cs/examples) and combine
`ark-ar1cs` + `ark-ar1cs-build` to demonstrate
`Circuit → .ar1cs → setup → .arzkey → prove → verify`. The opt-in
`test_fixtures` module on `ark-ar1cs` (gated behind the `test-fixtures`
feature) provides shared property-test fixtures.

## Core principles

1. **Defining Constraint.** Every sibling artifact embeds `ar1cs_blake3` —
   the Blake3 hash of the canonical `.ar1cs` body. This hash binds *circuit
   identity*. It is the single sanctioned cross-binding mechanism. Anything
   that tries to bind sibling artifacts a different way is rejected.

   *Scope limit:* `ar1cs_blake3` does **not** bind ceremony identity. Two
   trusted setups for the same `.ar1cs` produce the same hash and different
   `(PK, VK)`. Deployments that need to detect a ceremony swap must pin
   the `.arzkey` hash itself out of band.

2. **Core Tech.** Versioned envelope + content-addressed cross-binding +
   forward-only versioning, applied to byte interfaces that cross
   component boundaries. The methodology is scheme-agnostic and survives
   any future move beyond Groth16.

3. **Scope Rule.** Three crates, two artifact formats, split R/B
   (runtime / build-time). Anything else is a workflow adapter or a
   test fixture.

## Quick example

```rust
use ark_ar1cs::format::importer::ImportedCircuit;
use ark_ar1cs::format::{ArcsFile, CurveId};
use ark_ar1cs::{prove, verify};
use ark_ar1cs_build::{export_circuit, from_setup_output};
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;

let mut rng = /* any Rng + CryptoRng — e.g. StdRng::from_seed(...) */;

// 1. Export the circuit to .ar1cs bytes (no key yet).
let mut arcs_bytes = Vec::new();
export_circuit::<Fr, _, _>(build_circuit(), CurveId::Bn254, &mut arcs_bytes)?;

// 2. Re-import as a ConstraintSynthesizer and run trusted setup.
let imported = ImportedCircuit::<Fr>::from_reader(
    &mut &arcs_bytes[..],
    CurveId::Bn254,
)?;
let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
    imported,
    &mut rng,
)?;

// 3. Wrap (matrices, pk) as a single .arzkey. vk = pk.vk.clone() internally.
let arcs = ArcsFile::<Fr>::read(&mut &arcs_bytes[..])?;
let arzkey = from_setup_output::<Bn254>(arcs, pk);

// 4. Compute the full assignment for a concrete instance.
//    Layout: [F::ONE, instance_vars..., witness_vars...].
let full_assignment = compute_full_assignment_for(&build_circuit());

// 5. Prove and verify — no circuit object at prove time.
let proof = prove(&arzkey, &full_assignment, &mut rng)?;
let instance = &full_assignment[1..arzkey.header.num_instance_variables as usize];
assert!(verify(&arzkey, instance, &proof)?);
```

A runnable end-to-end version of this walkthrough lives in
[`crates/ark-ar1cs/examples/01_export_setup_prove_verify.rs`](crates/ark-ar1cs/examples/01_export_setup_prove_verify.rs).

## Format envelope (shared by all three)

```text
[magic][version: u8][curve_id: u8][reserved][format-specific header]
[body]
[Blake3 trailer: 32 bytes — hash of header + body]
```

- `version` is `0x00` (v0). Readers reject unknown versions with a typed
  `UnsupportedVersion` error. Migration to v1 is a separate tool, not a
  transparent reader feature.
- `reserved` bytes **must be zero** on read. Non-zero bytes are rejected
  with `ReservedNotZero` so each circuit has exactly one canonical byte
  sequence.
- The trailer covers `header || body`. A single bit flip anywhere in the
  envelope is detected as `ChecksumMismatch`.
- Each format has a hard size cap. Length fields in the header are
  validated against the cap **before** any `Vec::with_capacity` so a
  crafted file with `length = u64::MAX` is rejected before allocation.

| Format | Header size | Body | Max size |
|--------|------------:|------|---------:|
| `.ar1cs`  | 57 bytes  | matrix A \| B \| C (canonical sort)  | 256 MiB |
| `.arzkey` | 128 bytes | embedded `.ar1cs` \| vk \| pk        | 8 GiB   |

See each crate's source for the exact byte layout, the error model, and
the partial-read patterns. The witness now travels as a raw
`Vec<E::ScalarField>` via `ark-serialize` (no envelope) between the
`circuit.wasm` generator and the Rust prover.

## Curve support

| `CurveId`           | Byte | Status |
|---------------------|-----:|--------|
| `CurveId::Bn254`    | `0x01` | Stable, e2e + property-test coverage |
| `CurveId::Bls12_381`| `0x02` | Stable, e2e cross-curve coverage     |
| `CurveId::Bls12_377`| `0x03` | Enum entry only — opt-in when a consumer asks |

The format and prover are generic over `E: Pairing`. The `curve_id` byte
is cross-checked everywhere the curve matters: importer rejects mismatch
with `CurveIdMismatch`, prover's bind-check rejects with
`ArtifactMismatchReason::CurveId`.

## Wasm support

`ark-ar1cs` and `ark-ar1cs-wasm-witness` build clean on
`wasm32-unknown-unknown` (CI-enforced). `ark-ar1cs-build` is
**native-only** by design — it pulls in the arkworks setup machinery
and is meant to run on the CI host that produces deployable
`.ar1cs`/`.arzkey` artifacts, not in the browser.

The intended deployment shape: a `circuit.wasm` witness generator
(produced by `ark-ar1cs-wasm-witness`) computes the full assignment and
serializes it as `Vec<E::ScalarField>` via `ark-serialize`. A Rust
prover (native or wasm) consumes those bytes together with `.arzkey`.

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all -- -D warnings
cargo build --target wasm32-unknown-unknown \
    -p ark-ar1cs -p ark-ar1cs-wasm-witness
```

Property tests run at ≥1000 iterations under `cargo test --release`.

## Distribution

This is a public-source library project. Crates are not currently
published to crates.io; consumers depend on git references. A future
crates.io publication is a release-time decision, not a code-level
constraint. License: MIT OR Apache-2.0.
