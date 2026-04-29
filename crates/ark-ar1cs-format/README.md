# ark-ar1cs-format

Core byte format for arkworks R1CS constraint systems. This crate defines
the `.ar1cs` envelope: header, three matrices, Blake3 trailer. It is one
of the [four core surface crates](../../README.md#project-surface) of
ark-ar1cs.

This crate ships the `body_blake3()` method that is the **single
sanctioned source** of the `ar1cs_blake3` value embedded in `.arzkey` and
`.arwtns`. Sibling crates and consumers must call it; re-implementing the
hash externally is incorrect because the canonical body bytes include the
header and require the row-internal sort.

## Byte layout (v0)

```text
[header: 57 bytes]
  magic                    [6] = b"AR1CS\0"
  version                  [1] = 0x00
  curve_id                 [1]   0x01=BN254, 0x02=BLS12-381, 0x03=BLS12-377
  reserved                 [1]   MUST be zero on read (ReservedNotZero)
  num_instance_variables   [8 LE]   includes implicit "1" wire at index 0
  num_witness_variables    [8 LE]
  num_constraints          [8 LE]
  a_non_zero               [8 LE]
  b_non_zero               [8 LE]
  c_non_zero               [8 LE]
[matrix A]                       canonical sort (see below)
[matrix B]                       canonical sort
[matrix C]                       canonical sort
[trailer: 32 bytes]              blake3(header || matrix_a || matrix_b || matrix_c)
```

Each matrix is encoded as:

```text
num_rows: u64 LE
for each row:
    num_entries: u64 LE
    for each (coeff, var_idx):
        coeff   = F::serialize_compressed(...)
        var_idx = u64 LE
```

### Canonical sort (ARCH-1)

`write_matrix` sorts each row's `(coeff, var_idx)` pairs by `var_idx`
ascending **before** serialization. Two `ConstraintMatrices` with
identical content but reordered pairs within a row therefore produce
byte-identical `.ar1cs` output and identical `body_blake3()` values. This
is what makes `ar1cs_blake3` a stable circuit identifier.

### `body_blake3()`

```rust
pub fn body_blake3(&self) -> [u8; 32];
```

Returns `blake3(header || matrix_a || matrix_b || matrix_c)`. The same
value appears in the file's own trailer and **must** be embedded in any
sibling format that references this file (`.arzkey.header.ar1cs_blake3`,
`.arwtns.header.ar1cs_blake3`).

## Error model

`ArcsError` is `#[non_exhaustive]`. The current variants:

| Variant | Cause |
|---------|-------|
| `InvalidMagic`         | Magic bytes are not `b"AR1CS\0"` |
| `UnsupportedVersion(u8)` | `version` byte is not `0x00` |
| `UnsupportedCurve(u8)`   | `curve_id` byte is outside `0x01..=0x03` |
| `CurveIdMismatch { expected, found }` | Caller passed `expected_curve_id` to the importer and the file has a different curve |
| `ReservedNotZero`        | The reserved header byte is non-zero — the canonical-byte invariant |
| `ChecksumMismatch`       | Blake3 trailer disagrees with the computed body hash |
| `FileTooLarge`           | File exceeds `MAX_FILE_BYTES = 2 GiB` |
| `ValidationFailed(String)` | Header counts disagree with matrix dimensions, oversize entry, out-of-bounds column index, or trailing bytes between matrices and trailer (canonical-serialization invariant) |
| `Serialization(...)`     | Forwarded from `ark_serialize` |
| `Io(...)`                | Forwarded from `std::io::Error` |

`read` validates the trailer first, then parses, then runs `validate()`
to cross-check header counts, non-zero totals, and column-index bounds.
`read_matrix` enforces row/entry budgets **before** any `Vec` allocation,
so a crafted file declaring `num_rows = u64::MAX` is rejected without
allocation.

## Workflow

```rust
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_bn254::Fr;

// Build from arkworks ConstraintMatrices
let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);

// Identity hash for sibling formats
let id = arcs.body_blake3();

// Round-trip
let mut bytes = Vec::new();
arcs.write(&mut bytes)?;
let parsed = ArcsFile::<Fr>::read(&mut &bytes[..])?;
assert_eq!(parsed, arcs);
```

## Limits and security

- `MAX_FILE_BYTES = 2 GiB`. Files at or above the cap return
  `FileTooLarge` before any parsing.
- Trailer is a Blake3 hash, not a MAC. It detects accidental corruption
  (bit flips, truncation) but an attacker with write access to the file
  can compute a valid trailer.
- 32-bit targets are not supported. Internal arithmetic uses
  `u64 as usize`; truncation on 32-bit could mis-allocate.
- The format encodes only the constraint system. Witness assignments live
  in `.arwtns` (see [`ark-ar1cs-wtns`](../ark-ar1cs-wtns)); proving and
  verifying keys live in `.arzkey` (see
  [`ark-ar1cs-zkey`](../ark-ar1cs-zkey)).

## Adapters

The `exporter` and `importer` workflow adapters live as modules inside
this crate (no extra dependency to declare beyond `ark-ar1cs-format`):

- `ark_ar1cs_format::exporter::export_circuit` — synthesize a circuit
  in setup mode and write `.ar1cs` bytes in one call.
- `ark_ar1cs_format::importer::ImportedCircuit` — read `.ar1cs` as a
  `ConstraintSynthesizer` (takes `expected_curve_id` and rejects
  `CurveIdMismatch`).

Shared property-test fixtures (`make_test_matrices`,
`arb_matrices_with_assignment`) live under
`ark_ar1cs_format::test_fixtures::*` and are gated behind the optional
`test-fixtures` feature so default builds (and wasm32 builds) stay
proptest-free.

## See also

- [Repository root](../../README.md) — workspace overview, format envelope, three core principles.

## License

MIT OR Apache-2.0.
