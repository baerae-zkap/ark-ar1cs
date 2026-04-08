# TODOS

Work items deferred from active development.

---

## ark-ar1cs-format

### P3: Fuzz target for binary parser

**What:** Add a `cargo-fuzz` target for `ArcsFile::read` with arbitrary byte input.

**Why:** The format is a binary parser accepting untrusted bytes. Property-based testing
or fuzzing is table stakes for catching edge cases in bounds checks, checksum verification,
and field element deserialization paths. The bounded-allocation and checksum work in v0.1.1
reduces the blast radius, but systematic fuzzing provides coverage the test suite can't.

**How to start:** `cargo install cargo-fuzz`, create `fuzz/fuzz_targets/read_arcs_file.rs`
targeting `ArcsFile::<ark_bn254::Fr>::read(&mut data)`. Run with `cargo fuzz run read_arcs_file`.

**Completeness without this:** 7/10 — hardened, but untested against random byte sequences.

---

### P3: v1 format versioning with forward-compatible sections

**What:** Design v1 as a section-based layout (TLV sections or a `header_size` field) so
v0 readers can detect and skip unknown extensions gracefully.

**Why:** The current `reserved` byte is insufficient for forward-compatible evolution.
A v1 that changes the matrix wire format has no way to be distinguishable from a v0 file
that happens to have garbage in the reserved byte. Versioned section skipping (like ELF
or protobuf) lets future readers decide whether to hard-error or skip unknown sections.

**Context:** v0 has a `version: u8` field. v0 readers already return `UnsupportedVersion`
for any version > 0x00. Adding a `header_size` field in v1 would let v0 readers detect
the mismatch and fail clearly, while v1 readers could use the size to skip forward.

**Not blocking:** v0 is the only deployed version. No migration needed until v1 is designed.

---

## Completed

- **GitHub Actions CI** — `cargo test --all` + `cargo clippy -- -D warnings` on push/PR.
  Completed: v0.1.1 (2026-04-08)
