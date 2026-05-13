# ark-ar1cs-prover

Circuit-agnostic Groth16 prover and verifier consuming `.arzkey` artifacts
and a raw `&[F]` full assignment. One of the core surface crates of
ark-ar1cs.

`prove` never re-runs the original `ConstraintSynthesizer`. It reads the
matrices and the proving key from `.arzkey`, R1CS-pre-flights the caller's
full-assignment slice, and hands the matrices and assignment to
`Groth16::create_proof_with_reduction_and_matrices`. The verifier mirrors
this on the read side, against the verifying key embedded in `.arzkey`.

## API

```rust
pub fn prove<E: Pairing, R: Rng + CryptoRng>(
    arzkey:          &ArzkeyFile<E>,
    full_assignment: &[E::ScalarField],   // [F::ONE, instance..., witness...]
    rng:             &mut R,
) -> Result<Proof<E>, ProverError>;

pub fn verify<E: Pairing>(
    arzkey:        &ArzkeyFile<E>,
    public_inputs: &[E::ScalarField],     // excludes implicit "1"
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
1. length check: full_assignment.len() == arzkey.num_instance_variables
                                          + arzkey.num_witness_variables
2. preflight::check_r1cs_satisfaction(arzkey.arcs(), full_assignment)?;
3. let r, s = E::ScalarField::rand(rng);
4. Groth16::create_proof_with_reduction_and_matrices(
       arzkey.pk(), r, s,
       &arzkey.arcs().clone().into_matrices(),
       arzkey.header.num_instance_variables as usize,
       arzkey.header.num_constraints as usize,
       full_assignment,
   )
```

### Optional header binding (caller's one-line responsibility)

`prove` does **not** automatically validate that the loaded `.arzkey`
matches a specific expected circuit identity. Production callers who
load `.arzkey` bytes from disk or network should compare
`arzkey.header.ar1cs_blake3` against an out-of-band expected value
(e.g. from a deployment manifest) before calling `prove`:

```rust
use ark_ar1cs_prover::{ArtifactMismatchReason, ProverError};

if arzkey.header.ar1cs_blake3 != expected_ar1cs_blake3 {
    return Err(ProverError::ArtifactMismatch {
        reason: ArtifactMismatchReason::Ar1csBlake3,
    });
}
prove(&arzkey, &full_assignment, &mut rng)?;
```

Wrong-curve `.arzkey` files are rejected one layer earlier:
`ArzkeyFile::<E>::read` validates header `curve_id` against type-level
`E` at parse time, so the prover never sees a wrong-curve artifact.

### R1CS pre-flight is mandatory

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
| `ArtifactMismatch { reason }` | Not raised automatically by `prove`. Available for callers performing their own header binding (see "Optional header binding" above). |
| `AssignmentNotSatisfying { row }` | R1CS pre-flight failed at `row` |
| `CorruptArtifact` | Internal invariant violated; effectively unreachable for files produced by `read`/`from_setup_output` |
| `WitnessLengthMismatch { expected, got }` | `full_assignment.len()` disagrees with what the proving key expects |
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
- [Repository root](../../README.md) — workspace overview, three core
  principles.

## License

MIT OR Apache-2.0.
