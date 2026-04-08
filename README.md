# ark-ar1cs

Portable Groth16 constraint system format for [arkworks](https://github.com/arkworks-rs) circuits.

Export a finalized R1CS constraint system once, then run Groth16 trusted setup from
the file alone — no original circuit code required.

## Crates

| Crate | Description |
|-------|-------------|
| `ark-ar1cs-format` | Core format: header, matrices, Blake3 checksum, validation |
| `ark-ar1cs-exporter` | Synthesize a circuit and write an `.ar1cs` file |
| `ark-ar1cs-importer` | Read an `.ar1cs` file as a `ConstraintSynthesizer` |

## Usage

### Export a circuit

```rust
use ark_ar1cs_exporter::export_circuit;
use ark_ar1cs_format::CurveId;
use ark_bn254::Fr;
use std::fs::File;

let mut writer = File::create("my_circuit.ar1cs")?;
export_circuit::<Fr, _, _>(my_circuit, CurveId::Bn254, &mut writer)?;
```

### Import and run setup

```rust
use ark_ar1cs_importer::ImportedCircuit;
use ark_ar1cs_format::CurveId;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;

let mut file = std::fs::File::open("my_circuit.ar1cs")?;
let circuit = ImportedCircuit::<Fr>::from_reader(&mut file, CurveId::Bn254)?;

let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
    circuit,
    &mut rng,
)?;
```

## File Format

`.ar1cs` files use a fixed binary layout:

```
[header: 57 bytes]
  magic:                b"AR1CS\x00" (6 bytes)
  version:              u8 = 0x00
  curve_id:             u8 (0x01=BN254, 0x02=BLS12-381, 0x03=BLS12-377)
  reserved:             u8 = 0x00
  num_instance_variables: u64 LE  (includes implicit "1" wire at index 0)
  num_witness_variables:  u64 LE
  num_constraints:        u64 LE
  a_non_zero:             u64 LE
  b_non_zero:             u64 LE
  c_non_zero:             u64 LE
[matrix A: custom serialization]
[matrix B: custom serialization]
[matrix C: custom serialization]
[Blake3 checksum: 32 bytes]
```

Each matrix is encoded as:
- `num_rows: u64 LE`
- For each row: `num_entries: u64 LE`, then per entry: `coeff` (CanonicalSerialize compressed) + `var_idx: u64 LE`

The 32-byte Blake3 trailer is the hash of all preceding bytes.
`ArcsFile::read` verifies the checksum before parsing. Files larger than 256 MB are rejected.

### Security notes

- The checksum detects accidental corruption (bit flips, truncation). It is **not** a
  MAC — an attacker with write access to the file can forge a valid checksum.
- Maximum file size: 256 MB (`ark_ar1cs_format::MAX_FILE_BYTES`). Files larger than this
  return `ArcsError::FileTooLarge` before any parsing.
- 32-bit targets are not officially supported. The format uses `u64` values for matrix
  counts; `u64 as usize` truncation on 32-bit would produce incorrect behaviour.

## Supported Curves

| `CurveId` | arkworks crate |
|-----------|---------------|
| `Bn254` (0x01) | `ark-bn254` |
| `Bls12_381` (0x02) | `ark-bls12-381` |
| `Bls12_377` (0x03) | `ark-bls12-377` |

## Testing

```bash
cargo test --all
cargo clippy --all -- -D warnings
```

## License

Licensed under MIT OR Apache-2.0.
