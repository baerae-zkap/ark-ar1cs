# ark-ar1cs-wtns

The `.arwtns` witness format: one assignment for one proof, packaged for
transport across a component boundary. One of the [four core surface
crates](../../README.md#project-surface) of ark-ar1cs.

Despite the name, `.arwtns` carries **both** public-input (instance) and
private-witness assignments — arkworks' matrix prover requires the full
assignment vector for proof construction. The body distinguishes the
two slices via `num_instance` / `num_witness` so future
public-input-only readers can do so without parsing the witness portion.

## Why a file format and not a struct

A `Vec<F>` is enough when the witness producer and the prover live in
the same Rust binary. ark-ar1cs targets the case where they don't — for
example, a wasm witness generator built and uploaded to S3 separately
from the Rust prover that consumes its output. The two components have
independent build pipelines, independent versioning cadences, and
independent artifact stores. A versioned envelope with content-addressed
cross-binding is therefore not a convenience but a structural
requirement: without it, "wrong wasm produced this witness" is a silent
failure mode.

The wasm witness generator is expected to depend on this crate and call
`ArwtnsFile::write` — it must **not** re-implement the envelope.

## Byte layout (v0)

```text
[header: 64 bytes]
  magic                    [6] = b"ARWTNS"
  version                  [1] = 0x00
  curve_id                 [1]
  reserved                 [8]   MUST be zero on read (ReservedNotZero)
  ar1cs_blake3            [32]   blake3 of canonical .ar1cs body
                                 — binds CIRCUIT identity
  num_instance             [8 LE]   excludes implicit "1" wire (variable index 0)
  num_witness              [8 LE]
[body]
  instance_assignments    num_instance × Fr::serialize_compressed
  witness_assignments     num_witness  × Fr::serialize_compressed
[trailer: 32 bytes]              blake3(header || body)
```

`ARWTNS_HEADER_SIZE = 64` and `MAX_ARWTNS_BYTES = 256 MiB` are exported
constants.

### The implicit "1" wire is excluded from the body

Variable index 0 in arkworks is always the constant `1`. The `.arwtns`
body **omits it**; the prover prepends it during full-assignment
reconstruction:

```rust
pub fn full_assignment_with_one_wire(&self) -> Vec<F>;
// returns [F::ONE, instance..., witness...]
```

The bind-check rule in `ark-ar1cs-prover` reflects this:

```text
arwtns.num_instance + arwtns.num_witness
    == arzkey.num_instance_variables - 1 + arzkey.num_witness_variables
```

A mismatch is rejected with `ArtifactMismatchReason::CountMismatch`.

## API

```rust
impl<F: PrimeField> ArwtnsFile<F> {
    pub fn from_assignments(
        curve_id:     CurveId,
        ar1cs_blake3: [u8; 32],
        instance:     &[F],   // does NOT include the implicit "1"
        witness:      &[F],
    ) -> Self;

    pub fn read<R: Read>(r: &mut R)          -> Result<Self, ArwtnsError>;
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArwtnsError>;
    pub fn validate(&self)                   -> Result<(), ArwtnsError>;

    pub fn full_assignment_with_one_wire(&self) -> Vec<F>;
}
```

`from_assignments` is the only constructor. The `ar1cs_blake3` argument
**must** come from the matching `arcs.body_blake3()` (or the
`arzkey.header.ar1cs_blake3` value, since they agree by construction);
re-implementing the hash externally is incorrect because the canonical
body bytes include the header and require the row-internal sort.

## Error model

`ArwtnsError` is `#[non_exhaustive]`. Each malformed-input scenario maps
to a distinct typed variant — error matching is exact:

| Variant | Cause |
|---------|-------|
| `BadMagic` | Magic bytes are not `b"ARWTNS"` |
| `UnsupportedVersion(u8)` | `version` is not `0x00` |
| `ReservedNotZero` | Reserved bytes are non-zero |
| `CurveMismatch { header, embedded }` | Reserved for future cross-checks |
| `Ar1csBlake3Mismatch` | Reserved for explicit re-hash checks |
| `ChecksumMismatch` | Blake3 trailer disagrees with the computed hash |
| `FileTooLarge` | File or projected body size exceeds `MAX_ARWTNS_BYTES = 256 MiB` |
| `TrailingBytes(u64)` | Bytes remain between the body and the trailer |
| `CountMismatch { field, header, actual }` | Header `num_instance`/`num_witness` disagrees with the in-memory vector length |
| `BodyLengthMismatch { expected, actual }` | `(num_instance + num_witness) × Fr::compressed_size` disagrees with the body bytes between header end and trailer |
| `Format(...)` | Forwarded from `ark_ar1cs_format::ArcsError` |
| `Serialization(...)` | Forwarded from `ark_serialize` |
| `Io(...)` | Forwarded from `std::io::Error` |

Length fields are validated against the cap **before** any allocation —
a crafted header with `num_witness × elem_size > MAX_ARWTNS_BYTES` is
rejected without `Vec::with_capacity`.

## One file = one proof

There is **no** multi-instance container in v0. Multiple instances are
handled at the call site by looping over `prove`. There is also no
`prove_batch` in `ark-ar1cs-prover`.

## Wasm builds

`cargo build --target wasm32-unknown-unknown -p ark-ar1cs-wtns` is a
CI-enforced gate. The wasm witness generator targeting browsers depends
on this crate to produce `.arwtns` bytes — see
[`crates/ark-ar1cs-prover/README.md`](../ark-ar1cs-prover/README.md) for
the wasm prover side.

## See also

- [`ark-ar1cs-format`](../ark-ar1cs-format) — defines `ArcsFile` and
  `body_blake3()`.
- [`ark-ar1cs-zkey`](../ark-ar1cs-zkey) — paired setup-output format.
- [`ark-ar1cs-prover`](../ark-ar1cs-prover) — consumes `.arzkey + .arwtns`
  and emits `Proof<E>`.
- [Repository root](../../README.md) — workspace overview.

## License

MIT OR Apache-2.0.
