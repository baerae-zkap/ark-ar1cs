# ark-ar1cs-prover

Circuit-agnostic Groth16 prover and verifier consuming `.arzkey + .arwtns`
artifacts. One of the [four core surface
crates](../../README.md#project-surface) of ark-ar1cs.

`prove` never re-runs the original `ConstraintSynthesizer`. It reads the
matrices and the proving key from `.arzkey`, the assignment from
`.arwtns`, cross-checks them with four bind rules, R1CS-pre-flights the
assignment, and hands the matrices and assignment to
`Groth16::create_proof_with_reduction_and_matrices`. The verifier mirrors
this on the read side, against the verifying key embedded in `.arzkey`.

## API

```rust
pub fn prove<E: Pairing, R: Rng + CryptoRng>(
    arzkey: &ArzkeyFile<E>,
    arwtns: &ArwtnsFile<E::ScalarField>,
    rng:    &mut R,
) -> Result<Proof<E>, ProverError>;

pub fn verify<E: Pairing>(
    arzkey:        &ArzkeyFile<E>,
    public_inputs: &[E::ScalarField],   // excludes implicit "1"
    proof:         &Proof<E>,
) -> Result<bool, ProverError>;
```

`Ok(true)` from `verify` means the proof verifies against `arzkey.vk()`.
`Ok(false)` means the proof is well-formed but rejects this statement
(e.g., wrong public input). `Err(...)` is reserved for genuine framework
errors (e.g., a malformed VK), which `ArzkeyFile::read` already
guarantees against — this branch is effectively unreachable for files
that round-tripped through the envelope.

There is no `prove_batch`. Multiple instances are handled at the call
site by looping over `prove`.

## What `prove` does (and why)

```text
1. bind_check(&arzkey, &arwtns)
2. let z = arwtns.full_assignment_with_one_wire();
3. preflight::check_r1cs_satisfaction(arzkey.arcs(), &z)?;
4. let r, s = E::ScalarField::rand(rng);
5. Groth16::create_proof_with_reduction_and_matrices(
       arzkey.pk(), r, s,
       &arzkey.arcs().clone().into_matrices(),
       arzkey.header.num_instance_variables as usize,
       arzkey.header.num_constraints as usize,
       &z,
   )
```

### Step 1 — Four bind rules (cheap → expensive)

Each rule maps to a distinct `ArtifactMismatchReason` variant. Tests
match exactly on the variant — never on a string prefix.

| Rule | Cost | Failure variant |
|------|------|-----------------|
| 1. `arzkey.curve_id == arwtns.curve_id`                              | `O(1)` | `CurveId { arzkey, arwtns }` |
| 2. `arzkey.ar1cs_blake3 == arwtns.ar1cs_blake3`                      | `O(1)` 32-byte memcmp | `Ar1csBlake3` |
| 4. `arwtns.num_instance + arwtns.num_witness == arzkey.num_instance_variables - 1 + arzkey.num_witness_variables` | `O(1)` | `CountMismatch { expected, got }` |
| 3. `arzkey.arcs().body_blake3() == arzkey.header.ar1cs_blake3`       | `O(ar1cs_byte_len)` | `SelfConsistency` |

Rule 3 runs **last** so wrong-curve and wrong-circuit pairs reject in
microseconds. Trailer integrity is not re-checked here — both
`ArzkeyFile::read` and `ArwtnsFile::read` have already verified their
respective Blake3 trailers at parse time.

#### Latency budgets

- **5a** — Rules 1, 2, 4 (`O(1)`): `< 1 ms` regardless of file size, on
  every target including wasm.
- **5b** — Rule 3 (`O(ar1cs_byte_len)`): `< 50 ms` on x86, `< 200 ms` on
  wasm for typical `<100 MB` embedded `.ar1cs`.
- **5c** — Parse-time trailer integrity (separate from bind-time, runs
  during `read`): `< 500 ms` on x86 for 1 GiB.

### Step 3 — R1CS pre-flight is mandatory

`Groth16::create_proof_with_reduction_and_matrices` does **not** verify
that the assignment satisfies the R1CS. Without an explicit pre-flight,
an invalid assignment produces an `Ok(Proof)` that always fails
verification — the worst kind of footgun in a SNARK toolkit.

`prove` therefore checks `Az[i] * Bz[i] == Cz[i]` for every row. The
first failure returns `ProverError::AssignmentNotSatisfying { row }`.
The cost is `O(sum of matrix nonzeros)`, dwarfed by the Groth16 MSM
that follows on a valid assignment.

External callers do **not** need to pre-validate the assignment; the
prover is responsible for catching this case.

## Error model

`ProverError` is `#[non_exhaustive]`:

| Variant | Cause |
|---------|-------|
| `ArtifactMismatch { reason }` | One of the four bind rules failed (see table above) |
| `AssignmentNotSatisfying { row }` | R1CS pre-flight failed at `row` |
| `CorruptArtifact` | Internal invariant violated; effectively unreachable for files produced by `read`/`from_setup_output` |
| `WitnessLengthMismatch { expected, got }` | Reconstructed full assignment length disagrees with what the matrices expect |
| `Groth16(...)` | Forwarded from `ark_relations::r1cs::SynthesisError` |
| `SerializationError(...)` | Forwarded from `ark_serialize` |

`ArtifactMismatchReason` is `#[non_exhaustive]`:
`CurveId { arzkey, arwtns }`, `Ar1csBlake3`, `SelfConsistency`,
`CountMismatch { expected, got }`.

## Curves

Generic over `E: Pairing`. Stable e2e coverage on BN254 and BLS12-381;
both run as part of `cargo test -p ark-ar1cs-prover`. BLS12-377 is in
the `CurveId` enum but no e2e test exists yet — opt-in when a consumer
asks.

## Wasm builds

The prover targets browsers as well as native. `cargo build --target
wasm32-unknown-unknown -p ark-ar1cs-prover` is a CI gate.

```toml
# Browser-side prover
[dependencies]
ark-ar1cs-prover = { ... }
getrandom = { version = "0.2", features = ["js"] }
```

`getrandom`'s `js` feature routes randomness through the browser's
`crypto.getRandomValues`. Native targets pull from the OS RNG via the
default `getrandom` backend; no special configuration needed.

The `Rng + CryptoRng` argument to `prove` lets the caller pick the
randomness source explicitly. For browser deployments using
`StdRng::from_os_rng()` is the simplest path.

## See also

- [`ark-ar1cs-format`](../ark-ar1cs-format) — `.ar1cs` envelope and
  `body_blake3()`.
- [`ark-ar1cs-zkey`](../ark-ar1cs-zkey) — `.arzkey` setup-output format
  consumed by `prove`.
- [`ark-ar1cs-wtns`](../ark-ar1cs-wtns) — `.arwtns` witness format
  consumed by `prove`.
- [Repository root](../../README.md) — workspace overview, three core
  principles.

## License

MIT OR Apache-2.0.
