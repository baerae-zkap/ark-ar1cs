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

The project surface is exactly **four core crates** producing **three
artifact formats**.

| Crate | Artifact | Role |
|-------|----------|------|
| [`ark-ar1cs-format`](crates/ark-ar1cs-format) | `.ar1cs` | Frozen R1CS matrices |
| [`ark-ar1cs-zkey`](crates/ark-ar1cs-zkey)     | `.arzkey` | Setup output (matrices + VK + PK) |
| [`ark-ar1cs-wtns`](crates/ark-ar1cs-wtns)     | `.arwtns` | One witness assignment |
| [`ark-ar1cs-prover`](crates/ark-ar1cs-prover) | `Proof<E>` | `prove(.arzkey, .arwtns) → Proof` |

Three workflow adapters sit beside the surface: `ark-ar1cs-exporter`
(synthesize → `.ar1cs`), `ark-ar1cs-importer` (`.ar1cs` →
`ConstraintSynthesizer`), and `ark-ar1cs-test-fixtures` (shared test
matrices). They are useful but not part of the stable surface.

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

3. **Scope Rule.** Four crates, three formats. Anything else is a
   workflow adapter or a test fixture.

## Quick example

```rust
use ark_ar1cs_exporter::export_circuit;
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_importer::ImportedCircuit;
use ark_ar1cs_prover::{prove, verify};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
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
let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);

// 4. Compute the witness for a concrete instance.
//    `instance` excludes the implicit "1" wire — the prover prepends it.
let (instance, witness) = compute_assignment_for(&build_circuit());
let arwtns = ArwtnsFile::<Fr>::from_assignments(
    CurveId::Bn254,
    arzkey.header.ar1cs_blake3,
    &instance,
    &witness,
);

// 5. Prove and verify — no circuit object at prove time.
let proof = prove(&arzkey, &arwtns, &mut rng)?;
assert!(verify(&arzkey, &instance, &proof)?);
```

A runnable end-to-end version of this walkthrough lives in
[`crates/ark-ar1cs-examples/examples/01_export_setup_prove_verify.rs`](crates/ark-ar1cs-examples/examples/01_export_setup_prove_verify.rs).

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
| `.arzkey` | 128 bytes | embedded `.ar1cs` \| vk \| pk        | 1 GiB   |
| `.arwtns` | 64 bytes  | instance assignments \| witness assignments | 256 MiB |

See each crate's README for the exact byte layout, the error model, and
the partial-read patterns.

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

`ark-ar1cs-format`, `ark-ar1cs-wtns`, and `ark-ar1cs-prover` build clean on
`wasm32-unknown-unknown` (CI-enforced). The prover uses `getrandom`
features `["js"]` for browser builds. See
[`crates/ark-ar1cs-prover/README.md`](crates/ark-ar1cs-prover/README.md) for
the exact build command and randomness-source notes.

The intended deployment shape is: a wasm witness generator (built and
distributed separately, e.g. via S3) computes the assignment and writes
`.arwtns` bytes via `ArwtnsFile::write` — it does **not** re-implement
the envelope. A Rust prover (native or wasm) consumes those bytes
together with `.arzkey`.

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --target wasm32-unknown-unknown \
    -p ark-ar1cs-format -p ark-ar1cs-wtns -p ark-ar1cs-prover
```

Property tests run at ≥1000 iterations under `cargo test --release`.

## Distribution

This is a public-source library project. Crates are not currently
published to crates.io; consumers depend on git references. A future
crates.io publication is a release-time decision, not a code-level
constraint. License: MIT OR Apache-2.0.
