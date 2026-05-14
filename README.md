# ark-ar1cs

A portable Groth16 toolkit for [arkworks](https://github.com/arkworks-rs)
circuits. Serialize a finalized constraint system to `.ar1cs` bytes,
then prove from those bytes plus a separately-distributed
`ProvingKey<E>` — no original `ConstraintSynthesizer` needed at prove
time.

## Why

Standard arkworks Groth16 keeps the original Rust circuit in memory
through prove. That couples deployment to circuit code. ark-ar1cs
cuts the coupling: every step after `cs.finalize()` works from bytes
alone. This unlocks:

- Running `prove` on a host that doesn't know the circuit definition.
- Auditing a frozen constraint system as a byte artifact.
- Handing a `Vec<F>` witness from one component to another and proving
  from it without re-running the circuit.

This project is intentionally narrow: it owns the `.ar1cs` codec and
a single `prove` primitive. Manifests, signed envelopes, registries,
trust policies, and PK/VK packaging are out of scope — they belong in
the caller (see [`docs/artifact-trust-boundary.md`](docs/artifact-trust-boundary.md)).

## Project surface

After the feature-boundary migration, the workspace is **two crates**
producing **one artifact format**, split along the Core / Build-time
axis. A third bucket records what existed in earlier revisions and is
removed.

### Core (runtime)

[`ark-ar1cs`](crates/ark-ar1cs) — the runtime crate.

- `format::*` — `.ar1cs` codec: `ArcsFile<F>`, `ArcsHeader`,
  `CurveId`, `Matrix<F>`, canonical-sort writer, Blake3-trailer
  verifier, `ArcsError`. Exposes `ArcsFile::body_blake3()` as the
  single sanctioned cross-binding primitive (caller compares against
  manifest-pinned expected value).
- `format::importer::ImportedCircuit::from_reader` — `.ar1cs` →
  `ConstraintSynthesizer<F>` rehydrate, with curve-ID guard.
- `format::compat::{ConstraintMatrices, from_cs}` — bridge to
  `ark-relations` 0.6.
- `witness::synthesize_full_assignment<C, F>` — generic helper that
  runs a `ConstraintSynthesizer` to a full assignment
  (`[F::ONE, instance..., witness...]`). Also re-exported as
  `ark_ar1cs::synthesize_full_assignment`.
- `witness::WitnessError` — typed errors from
  `synthesize_full_assignment`. Also re-exported as
  `ark_ar1cs::WitnessError`.
- `prove<E, R>(pk, arcs, full_assignment, rng)` — circuit-agnostic
  Groth16 prover. Runs length check + R1CS preflight, then
  `Groth16::create_proof_with_reduction`. No identity binding inside
  the call; the caller binds with `arcs.body_blake3()`.
- `ProverError` — 4 variants: `WitnessLengthMismatch`,
  `AssignmentNotSatisfying { row }`, `Groth16`, `SerializationError`.

Builds clean on `wasm32-unknown-unknown` (CI-enforced).

### Build-time

[`ark-ar1cs-build`](crates/ark-ar1cs-build) — the build-time crate.

- `export_circuit::<F, C, W>(circuit, curve_id, writer)` — single
  responsibility: `ConstraintSynthesizer → .ar1cs` bytes.
- `ExportError` — typed errors from the export pass.

Native-only by design (pulls arkworks setup machinery). Meant to run
on the CI host that produces deployable `.ar1cs` artifacts, not in the
browser.

### Removed / out of scope

The following existed in earlier revisions of this workspace and are
removed by the feature-boundary migration. Each is now the caller's
or setup producer's responsibility. See
[`docs/artifact-trust-boundary.md`](docs/artifact-trust-boundary.md)
for the rationale and recommended caller patterns.

| Component | Owned by | Replacement |
|---|---|---|
| `.arzkey` envelope (setup-output bundling) | Caller / deployment | Caller distributes `pk` (via arkworks `CanonicalSerialize`) and `.ar1cs` separately, binds them via `ar1cs_blake3` in the manifest. |
| `ark_ar1cs_build::from_setup_output` | Caller | `pk.serialize_uncompressed(&mut w)` + `arcs.write(&mut w)` directly. |
| `ark_ar1cs::verify` wrapper | Caller | `Groth16::verify_proof(&prepare_verifying_key(&pk.vk), &proof, public_inputs)` — one line of arkworks. |
| `ProverError::ArtifactMismatch { Reason }`, `ArtifactMismatchReason` | Caller | Caller-side enum on a caller-defined identity policy. |
| `ProverError::CorruptArtifact` | Removed | Unreachable after `.arzkey` removal. |
| `fast-prove` cargo feature | Caller | `ProvingKey::deserialize_uncompressed_unchecked` directly. The trust decision is the caller's. |
| `ark-ar1cs-wasm-witness` crate (the `WitnessGenerator` trait, `export_witness_generator!` macro, wasm ABI, `WitnessAbiCode`, packed/mock fixtures) | Consumer | Consumer implements its own wasm export shape. |
| Manifest schema, signed manifest, artifact registry, deployment trust policy | Application / operator | Out-of-band. Format unconstrained by this library. |
| PK / VK deserialization wrappers, partial-read VK helper | Caller | `ark-groth16` already provides `CanonicalSerialize` / `CanonicalDeserialize`. |
| Automatic `ar1cs_blake3` comparison inside `prove` | Caller | Caller-side one-line compare against manifest-pinned expected value. |
| App-specific witness derivation (input → witness) | Consumer | Witness logic is application code. |

`.arzkey`-related examples (`02_round_trip_arzkey.rs`,
`04_wrap_pk_into_arzkey.rs`) and tests (`arzkey_round_trip.rs`,
`arzkey_negative.rs`, `arzkey_partial_read.rs`) are deleted alongside
the envelope. `bench-harness/`, `bench-results/`, and `dhat-heap.json`
(wasm-witness measurement artifacts) are deleted with the crate.

## Quick example

End-to-end workflow using only the post-migration surface (caller owns
PK distribution and identity binding):

```rust
use ark_ar1cs::format::importer::ImportedCircuit;
use ark_ar1cs::format::{ArcsFile, CurveId};
use ark_ar1cs::{prove, synthesize_full_assignment};
use ark_ar1cs_build::export_circuit;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::CanonicalSerialize;

let mut rng = /* any Rng + CryptoRng — e.g. StdRng::from_seed(...) */;

// 1. Build-time host: export the circuit to .ar1cs bytes.
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

// 3. Distribute pk via arkworks CanonicalSerialize directly.
let mut pk_bytes = Vec::new();
pk.serialize_uncompressed(&mut pk_bytes)?;
//    (The deployment manifest pins blake3(pk_bytes) and
//    blake3(arcs_body); see docs/artifact-trust-boundary.md.)

// 4. Prove-time host (may be a different machine, may not know the
//    circuit definition; only needs .ar1cs + pk bytes + an input).
let arcs = ArcsFile::<Fr>::read(&mut &arcs_bytes[..])?;
// Caller-side identity binding — the single sanctioned mechanism:
// if arcs.body_blake3() != MANIFEST.expected_ar1cs_blake3 { return ... }
let full = synthesize_full_assignment(build_circuit())?;
let proof = prove(&pk, &arcs, &full, &mut rng)?;

// 5. Verify directly with arkworks (no wrapper).
let pvk = prepare_verifying_key(&pk.vk);
let public_inputs = &full[1..arcs.header.num_instance_variables as usize];
assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof, public_inputs)?);
```

A runnable end-to-end version of this walkthrough lives in
[`crates/ark-ar1cs/examples/01_export_setup_prove_verify.rs`](crates/ark-ar1cs/examples/01_export_setup_prove_verify.rs)
(updated to the new surface in Commit 4 of the migration).

## Format envelope

```text
[magic][version: u8][curve_id: u8][reserved][format-specific header]
[body]
[Blake3 trailer: 32 bytes — hash of header + body]
```

- `version` is `0x00` (v0). Readers reject unknown versions with a
  typed `UnsupportedVersion` error. Migration to v1 is a separate
  tool, not a transparent reader feature.
- `reserved` bytes **must be zero** on read. Non-zero bytes are
  rejected with `ReservedNotZero` so each circuit has exactly one
  canonical byte sequence.
- The trailer covers `header || body`. A single bit flip anywhere in
  the envelope is detected as `ChecksumMismatch`.
- The size cap is validated against header length fields **before**
  any `Vec::with_capacity` so a crafted file with `length = u64::MAX`
  is rejected before allocation.

| Format | Header size | Body | Max size |
|--------|------------:|------|---------:|
| `.ar1cs`  | 57 bytes  | matrix A \| B \| C (canonical sort)  | 2 GiB |

See [`crates/ark-ar1cs/src/format/`](crates/ark-ar1cs/src/format) for
the exact byte layout, the error model, and the partial-read
patterns.

## Curve support

| `CurveId`           | Byte | Status |
|---------------------|-----:|--------|
| `CurveId::Bn254`    | `0x01` | Stable, e2e + property-test coverage |
| `CurveId::Bls12_381`| `0x02` | Stable, e2e cross-curve coverage     |
| `CurveId::Bls12_377`| `0x03` | Enum entry only — opt-in when a consumer asks |

The format and prover are generic over `E: Pairing`. The `curve_id`
byte is cross-checked by `ImportedCircuit::from_reader`, which rejects
mismatch with `CurveIdMismatch`. After the migration, the prover
enforces curve agreement at the **type level** — `ProvingKey<Bn254>`
cannot be passed alongside `ArcsFile<<Bls12_381 as Pairing>::ScalarField>`.

## Wasm support

`ark-ar1cs` builds clean on `wasm32-unknown-unknown` (CI-enforced).
`ark-ar1cs-build` is **native-only** by design — it pulls in the
arkworks setup machinery and is meant to run on the host that
produces deployable `.ar1cs` artifacts, not in the browser.

A wasm-based witness generator is no longer shipped from this
workspace. The previous `ark-ar1cs-wasm-witness` crate exported a
specific `WitnessGenerator` ABI shape; that shape is the consumer's
policy, not a generic primitive, and is removed.
[`docs/artifact-trust-boundary.md`](docs/artifact-trust-boundary.md)
records the new boundary: ark-ar1cs exposes
`synthesize_full_assignment<C, F>` as a generic helper for callers
that build their own witness export.

## Identity binding (caller-side)

ark-ar1cs does **not** automatically compare `arcs.body_blake3()`
against an expected hash inside `prove`. The expected hash is a
deployment concern, not a library argument.

The single sanctioned cross-binding pattern is one line on the caller
side:

```rust
if arcs.body_blake3() != MANIFEST.expected_ar1cs_blake3 {
    return Err(MyError::WrongCircuitArtifact);
}
```

For why this division (and what the prior `.arzkey` envelope was
actually buying — spoiler: not what it looked like), read
[`docs/artifact-trust-boundary.md`](docs/artifact-trust-boundary.md).

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --target wasm32-unknown-unknown -p ark-ar1cs
```

Property tests run at ≥1000 iterations under `cargo test --release`.

The workspace pins `rust-version = "1.81"` and enforces
`[workspace.lints.rust] unsafe_code = "deny"`,
`[workspace.lints.clippy] unwrap_used = "deny"`. Test code
self-exempts via `#![cfg_attr(test, allow(clippy::unwrap_used,
clippy::expect_used))]` per crate.

## Distribution

This is a public-source library project. Crates are not currently
published to crates.io; consumers depend on git references. A future
crates.io publication is a release-time decision, not a code-level
constraint. License: MIT OR Apache-2.0.
