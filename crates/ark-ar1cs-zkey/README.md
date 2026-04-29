# ark-ar1cs-zkey

The `.arzkey` setup-output format: matrices, verifying key, and proving
key bundled into one envelope. One of the [four core surface
crates](../../README.md#project-surface) of ark-ar1cs.

`(PK, VK)` is the atomic output of a Groth16 trusted setup. Distributing
them as separate files creates a class of "downloaded the wrong VK" bugs
that no header binding can prevent if the publishing operator
misconfigures. `.arzkey` removes that failure mode within a single
ceremony output by shipping both keys in one file with structural
consistency checks on read.

## Byte layout (v0)

```text
[header: 128 bytes]
  magic                    [6] = b"ARZKEY"
  version                  [1] = 0x00
  curve_id                 [1]   matches embedded .ar1cs and .arwtns
  reserved                 [8]   MUST be zero on read (ReservedNotZero)
  ar1cs_blake3            [32]   blake3 of canonical .ar1cs body
                                 (CIRCUIT identity — see boxout below)
  vk_blake3               [32]   blake3 of standalone vk_section bytes
                                 (authenticates header-only partial reads)
  ar1cs_byte_len           [8 LE]   exact length of embedded .ar1cs
  vk_byte_len              [8 LE]
  pk_byte_len              [8 LE]
  num_instance_variables   [8 LE]   mirrors .ar1cs header
  num_witness_variables    [8 LE]
  num_constraints          [8 LE]
[body]
  ar1cs                          embedded ArcsFile bytes
                                 (length = ar1cs_byte_len)
  vk                             VerifyingKey<E>::serialize_compressed
                                 (length = vk_byte_len; blake3 = header.vk_blake3)
  pk                             ProvingKey<E>::serialize_compressed
                                 (length = pk_byte_len; pk.vk MUST equal vk_section)
[trailer: 32 bytes]              blake3(header || body)
```

`ARZKEY_HEADER_SIZE = 128` and `MAX_ARZKEY_BYTES = 8 GiB` are exported
constants.

### Body order

`ar1cs → vk → pk` is intentional:

- **`ar1cs` first** so the prover can validate matrix dimensions before
  allocating large vectors; the self-consistency hash check fires up
  front.
- **`vk` second** so verifier-only consumers can read
  `[0, ARZKEY_HEADER_SIZE + ar1cs_byte_len + vk_byte_len)` and skip the
  PK tail. `vk_offset = ARZKEY_HEADER_SIZE + ar1cs_byte_len = 128 + ar1cs_byte_len`
  is computable from the outer 128-byte header alone — one HTTP Range
  request, not two.
- **`pk` last** because it is by far the largest section.

### VK duplication, by design

`ProvingKey<E>` already contains its own `vk` field. `pk.serialize_compressed`
therefore writes the same VK bytes as the standalone vk_section. v0
accepts this (~few KB on a multi-hundred-MB PK) and enforces consistency
on read:

- `header.vk_blake3 == blake3(vk_section)` else `VkBlake3Mismatch`.
- `pk.vk == vk_section` after both deserialize else `VkDuplicationDrift`.

It is therefore **structurally impossible** to load an `ArzkeyFile`
where the standalone VK and the VK embedded in the PK disagree.

## Defining-Constraint scope

> ### Circuit identity vs ceremony identity
>
> `ar1cs_blake3` binds **circuit identity**, not **ceremony identity**.
> Two trusted setups for the same `.ar1cs` produce the same
> `ar1cs_blake3` and different `(PK, VK)` pairs. Within one `.arzkey` the
> VK-duplication checks above eliminate PK/VK drift; **across** two
> `.arzkey` files for the same circuit, swapping ceremonies is **not**
> prevented at the format layer.
>
> Deployments that need to detect a ceremony swap must pin the `.arzkey`
> hash itself (or the VK hash) out of band — typically alongside the
> deployment-time configuration that names the file.

## Header-only partial-read (verifier extraction)

A verifier-only consumer can extract the VK by reading exactly
`ARZKEY_HEADER_SIZE + vk_byte_len` bytes — without parsing the embedded
`.ar1cs` body or the multi-hundred-MB PK. Authentication runs *before*
deserialization so unauthenticated bytes never reach
`VerifyingKey::deserialize_compressed`.

```rust
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use ark_ar1cs_zkey::{ArzkeyHeader, ARZKEY_HEADER_SIZE};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;

fn partial_read_vk_from_disk(path: &std::path::Path) -> VerifyingKey<Bn254> {
    let mut file = File::open(path).expect("open .arzkey");

    // 1. Read first ARZKEY_HEADER_SIZE (128) bytes only — outer header.
    let mut header_buf = [0u8; ARZKEY_HEADER_SIZE];
    file.read_exact(&mut header_buf)
        .expect("file must contain HEADER_SIZE bytes");
    let header = ArzkeyHeader::read(&mut &header_buf[..])
        .expect("ArzkeyHeader::read on a freshly-written .arzkey must succeed");

    // 2. Skip the embedded .ar1cs body without reading it.
    let vk_offset = ARZKEY_HEADER_SIZE as u64 + header.ar1cs_byte_len;
    file.seek(SeekFrom::Start(vk_offset))
        .expect("seek to vk_offset");

    // 3. Read exactly vk_byte_len bytes.
    let mut vk_section = vec![0u8; header.vk_byte_len as usize];
    file.read_exact(&mut vk_section)
        .expect("file must contain vk_byte_len bytes at vk_offset");

    // 4. Authenticate the slice BEFORE deserializing. Untrusted bytes never
    //    reach the deserializer.
    let computed = *blake3::hash(&vk_section).as_bytes();
    assert_eq!(computed, header.vk_blake3,
        "OV-3: vk_blake3 must authenticate the VK section before deserialize");

    // 5. Deserialize.
    VerifyingKey::<Bn254>::deserialize_compressed(&mut &vk_section[..])
        .expect("VerifyingKey::deserialize_compressed on authenticated bytes")
}
```

The same algorithm works over an HTTP server that supports byte-range
requests: fetch `[0, 128)`, parse the header, then fetch
`[vk_offset, vk_offset + vk_byte_len)`. The header itself is
authenticated transitively via `ar1cs_blake3` known out-of-band by the
verifier.

The structural enforcement (no embedded `.ar1cs` access during
partial-read) is checked by the test in
[`tests/partial_read.rs`](tests/partial_read.rs).

## API

```rust
impl<E: Pairing> ArzkeyFile<E> {
    /// vk = pk.vk.clone() internally — no separate vk argument.
    /// PK/VK drift inside a single .arzkey is structurally impossible.
    pub fn from_setup_output(arcs: ArcsFile<E::ScalarField>, pk: ProvingKey<E>) -> Self;

    pub fn read<R: Read>(r: &mut R)         -> Result<Self, ArzkeyError>;
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), ArzkeyError>;
    pub fn validate(&self)                   -> Result<(), ArzkeyError>;

    pub fn vk(&self)   -> &VerifyingKey<E>;
    pub fn pk(&self)   -> &ProvingKey<E>;
    pub fn arcs(&self) -> &ArcsFile<E::ScalarField>;
}
```

There is **no** `write_vk_only` helper. Consumers needing raw VK bytes
call `arzkey.vk().serialize_compressed(&mut w)` directly (one line, zero
new public surface). Partial-read consumers use the algorithm above.

## Error model

`ArzkeyError` is `#[non_exhaustive]`. Each malformed-input scenario maps
to a distinct typed variant — error matching is exact, never on a string
prefix:

| Variant | Cause |
|---------|-------|
| `BadMagic` | Magic bytes are not `b"ARZKEY"` |
| `UnsupportedVersion(u8)` | `version` is not `0x00` |
| `ReservedNotZero` | Reserved bytes are non-zero |
| `CurveMismatch { header, embedded }` | Outer header `curve_id` disagrees with embedded `.ar1cs` `curve_id` |
| `Ar1csLengthMismatch { header, actual }` | `ar1cs_byte_len` exceeds the body remainder |
| `VkLengthMismatch    { header, actual }` | `vk_byte_len` disagrees with the byte-count consumed by `VerifyingKey::deserialize_compressed` |
| `PkLengthMismatch    { header, actual }` | Same for `pk_byte_len` |
| `Ar1csBlake3Mismatch` | `header.ar1cs_blake3 ≠ embedded_arcs.body_blake3()` |
| `VkBlake3Mismatch`    | `header.vk_blake3 ≠ blake3(vk_section)` |
| `VkDuplicationDrift`  | `pk.vk ≠ vk_section` after deserialize |
| `ChecksumMismatch`    | Blake3 trailer disagrees with the computed hash |
| `FileTooLarge`        | File or any length field exceeds `MAX_ARZKEY_BYTES = 8 GiB` |
| `TrailingBytes(u64)`  | Bytes remain between the PK section and the trailer |
| `CountMismatch { field, header, actual }` | Header counts mirror the embedded `.ar1cs` header but disagree |
| `Format(...)` | Forwarded from `ark_ar1cs_format::ArcsError` |
| `Serialization(...)` | Forwarded from `ark_serialize` |
| `Io(...)` | Forwarded from `std::io::Error` |

Length fields are validated against the cap **before** any per-section
allocation — a crafted header with `vk_byte_len = u64::MAX` is rejected
without allocation.

## See also

- [`ark-ar1cs-format`](../ark-ar1cs-format) — defines `ArcsFile` and
  `body_blake3()`.
- [`ark-ar1cs-prover`](../ark-ar1cs-prover) — consumes `.arzkey + .arwtns`
  and emits `Proof<E>`.
- [Repository root](../../README.md) — workspace overview.

## License

MIT OR Apache-2.0.
