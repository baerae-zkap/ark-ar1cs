//! `export_witness_generator!` — emits the wasm ABI exports for a circuit.
//!
//! The macro generates four `#[no_mangle] pub extern "C"` functions on
//! `target_arch = "wasm32"`:
//!
//! - `wasm_alloc(size: u32) -> *mut u8`
//! - `wasm_free(ptr: *mut u8, size: u32)`
//! - `embedded_ar1cs_blake3(out_ptr_out: *mut *mut u8, out_len_out: *mut u32) -> i32`
//! - `witness_generator(input_ptr, input_len, host_blake3_ptr, out_ptr_out, out_len_out) -> i32`
//!
//! All buffers handed back through `out_ptr_out` are owned by the wasm
//! linear-memory allocator. The host MUST call `wasm_free(ptr, len)` after
//! copying the bytes out, or the wasm instance will leak that memory.
//!
//! Also exposes [`witness_generator_native`] — a host-callable entry point
//! that runs the same pipeline against in-process buffers. Used by the
//! integration tests in commit 4 and any non-wasm caller that wants the
//! identical postcard-in / witness-assignment-out contract.

use alloc::vec::Vec;

use ark_ar1cs_format::CurveId;
use ark_serialize::CanonicalSerialize;

use crate::abi::WitnessAbiCode;
use crate::WitnessGenerator;

/// Native (non-wasm) entry point with the same contract as the wasm
/// `witness_generator` export.
///
/// Returns the serialized full-assignment bytes on `Ok` (i.e. the
/// `ark-serialize` compressed `Vec<F>` representation of
/// `[F::ONE, instance..., witness...]`) and the matching [`WitnessAbiCode`]
/// on every failure path. Callers that drive the wasm version via
/// wasmer/wasmtime can use this to byte-identical-compare native vs. wasm
/// output.
pub fn witness_generator_native<G: WitnessGenerator>(
    input: &[u8],
    host_blake3: &[u8; 32],
    embedded_ar1cs_blake3: &[u8; 32],
) -> Result<Vec<u8>, WitnessAbiCode> {
    if input.is_empty() {
        return Err(WitnessAbiCode::MalformedInput);
    }
    if host_blake3 != embedded_ar1cs_blake3 {
        return Err(WitnessAbiCode::Blake3Mismatch);
    }
    let decoded: G::Input =
        postcard::from_bytes(input).map_err(|_| WitnessAbiCode::PostcardDecodeError)?;
    let circuit = G::build_circuit(decoded).map_err(|e| e.into())?;
    let full_assignment = crate::synthesize_full_assignment::<G::Circuit, G::Field>(circuit)
        .map_err(WitnessAbiCode::from)?;
    let mut buf: Vec<u8> = Vec::new();
    full_assignment
        .serialize_compressed(&mut buf)
        .map_err(|_| WitnessAbiCode::CircuitBuildError)?;
    Ok(buf)
}

/// Compile-time sanity check — every `WitnessGenerator` declares a curve.
/// Forces `G::CURVE_ID` to be reachable, which keeps the macro's link-time
/// requirement on the impl explicit at the call site.
pub const fn enforce_curve_id<G: WitnessGenerator>() -> CurveId {
    G::CURVE_ID
}

/// Emit the wasm ABI exports for `$gen` using `$blake3` as the embedded
/// `.ar1cs` blake3.
///
/// Usage:
///
/// ```ignore
/// ark_ar1cs_wasm_witness::export_witness_generator!(
///     generator       = MyWitnessGenerator,
///     embedded_blake3 = EMBEDDED_AR1CS_BLAKE3, // const [u8; 32]
/// );
/// ```
///
/// `$blake3` MUST resolve to a `&'static [u8; 32]` (typically a `pub const`
/// emitted from `build.rs`).
#[macro_export]
macro_rules! export_witness_generator {
    (
        generator       = $gen:ty
        $(, embedded_blake3 = $blake3:path )?
        $(,)?
    ) => {
        $crate::__export_witness_generator_inner!(
            $gen,
            $( $blake3 )?
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __export_witness_generator_inner {
    ($gen:ty, $blake3:path) => {
        // Force the impl to link.
        const _: $crate::ark_ar1cs_format_reexport::CurveId =
            $crate::macros::enforce_curve_id::<$gen>();

        #[cfg(target_arch = "wasm32")]
        #[no_mangle]
        pub extern "C" fn wasm_alloc(size: u32) -> *mut u8 {
            $crate::abi::wasm_alloc_impl(size)
        }

        #[cfg(target_arch = "wasm32")]
        #[no_mangle]
        pub unsafe extern "C" fn wasm_free(ptr: *mut u8, size: u32) {
            // SAFETY: contract delegated to the host — `ptr` and `size` must
            // come from a prior `wasm_alloc` / wasm-side allocation.
            unsafe { $crate::abi::wasm_free_impl(ptr, size) }
        }

        #[cfg(target_arch = "wasm32")]
        #[no_mangle]
        pub unsafe extern "C" fn embedded_ar1cs_blake3(
            out_ptr_out: *mut *mut u8,
            out_len_out: *mut u32,
        ) -> i32 {
            // SAFETY: out-pointers are host-owned writable slots by ABI
            // contract; the embedded constant is a 32-byte array.
            unsafe { $crate::abi::return_owned_buffer(&$blake3, out_ptr_out, out_len_out).as_i32() }
        }

        #[cfg(target_arch = "wasm32")]
        #[no_mangle]
        pub unsafe extern "C" fn witness_generator(
            input_ptr: *const u8,
            input_len: u32,
            host_blake3_ptr: *const u8,
            out_ptr_out: *mut *mut u8,
            out_len_out: *mut u32,
        ) -> i32 {
            $crate::macros::__witness_generator_export::<$gen>(
                input_ptr,
                input_len,
                host_blake3_ptr,
                &$blake3,
                out_ptr_out,
                out_len_out,
            )
            .as_i32()
        }
    };
    ($gen:ty,) => {
        const _: $crate::ark_ar1cs_format_reexport::CurveId =
            $crate::macros::enforce_curve_id::<$gen>();
    };
}

/// Implementation behind the generated `witness_generator` wasm export.
///
/// Kept out of the macro body so the generated code is one statement.
///
/// # Safety
///
/// The pointer arguments must satisfy the contract declared in the module
/// docs: input is `input_len` readable bytes (or null/zero for the malformed
/// path), host blake3 is 32 readable bytes (or null), out-pointers are
/// host-owned writable slots.
#[doc(hidden)]
pub unsafe fn __witness_generator_export<G: WitnessGenerator>(
    input_ptr: *const u8,
    input_len: u32,
    host_blake3_ptr: *const u8,
    embedded: &[u8; 32],
    out_ptr_out: *mut *mut u8,
    out_len_out: *mut u32,
) -> WitnessAbiCode {
    // SAFETY: pointer contract delegated to caller (the macro forwards the
    // wasm ABI args verbatim).
    let input = match unsafe { crate::abi::borrow_input(input_ptr, input_len) } {
        Ok(b) => b,
        Err(code) => return code,
    };
    // SAFETY: same contract.
    let blake_check = unsafe { crate::abi::check_host_blake3(host_blake3_ptr, embedded) };
    if blake_check != WitnessAbiCode::Ok {
        return blake_check;
    }
    let decoded: G::Input = match postcard::from_bytes(input) {
        Ok(v) => v,
        Err(_) => return WitnessAbiCode::PostcardDecodeError,
    };
    let circuit = match G::build_circuit(decoded) {
        Ok(c) => c,
        Err(e) => return e.into(),
    };
    let full_assignment = match crate::synthesize_full_assignment::<G::Circuit, G::Field>(circuit) {
        Ok(a) => a,
        Err(e) => return WitnessAbiCode::from(e),
    };
    // SAFETY: out-pointer contract delegated to caller.
    unsafe { crate::abi::return_full_assignment(&full_assignment, out_ptr_out, out_len_out) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::WitnessAbiCode;
    use ark_bn254::Fr;
    use ark_relations::gr1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
    };
    use ark_serialize::CanonicalDeserialize;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct ToyInput {
        x: u64,
        y: u64,
    }

    struct ToyCircuit {
        x: Fr,
        y: Fr,
        z: Fr,
    }

    impl ConstraintSynthesizer<Fr> for ToyCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let z = cs.new_input_variable(|| Ok(self.z))?;
            let x = cs.new_witness_variable(|| Ok(self.x))?;
            let y = cs.new_witness_variable(|| Ok(self.y))?;
            cs.enforce_r1cs_constraint(
                || LinearCombination::from(x),
                || LinearCombination::from(y),
                || LinearCombination::from(z),
            )?;
            Ok(())
        }
    }

    struct ToyGenerator;

    #[derive(Debug)]
    struct ToyError;
    impl From<ToyError> for WitnessAbiCode {
        fn from(_: ToyError) -> Self {
            WitnessAbiCode::CircuitBuildError
        }
    }

    impl WitnessGenerator for ToyGenerator {
        type Field = Fr;
        type Input = ToyInput;
        type Circuit = ToyCircuit;
        type Error = ToyError;
        const CIRCUIT_ID: &'static str = "toy-mul";
        const CURVE_ID: CurveId = CurveId::Bn254;

        fn public_input_names() -> &'static [&'static str] {
            &["z"]
        }

        fn build_circuit(input: Self::Input) -> Result<Self::Circuit, Self::Error> {
            let x = Fr::from(input.x);
            let y = Fr::from(input.y);
            Ok(ToyCircuit { x, y, z: x * y })
        }
    }

    #[test]
    fn native_path_produces_round_trippable_full_assignment() {
        use ark_ff::Field;
        let blake3 = [0xAB; 32];
        let input = ToyInput { x: 6, y: 7 };
        let bytes = postcard::to_allocvec(&input).unwrap();
        let out = witness_generator_native::<ToyGenerator>(&bytes, &blake3, &blake3).unwrap();
        let full: Vec<Fr> = Vec::<Fr>::deserialize_compressed(out.as_slice()).unwrap();
        // Layout: [F::ONE, z (instance == 42), x (witness == 6), y (witness == 7)].
        assert_eq!(full.len(), 4);
        assert_eq!(full[0], Fr::ONE);
        assert_eq!(full[1], Fr::from(42u64));
        assert_eq!(full[2], Fr::from(6u64));
        assert_eq!(full[3], Fr::from(7u64));
    }

    #[test]
    fn native_path_rejects_blake3_mismatch() {
        let embedded = [0xAB; 32];
        let host = [0xCD; 32];
        let bytes = postcard::to_allocvec(&ToyInput { x: 1, y: 2 }).unwrap();
        let err = witness_generator_native::<ToyGenerator>(&bytes, &host, &embedded).unwrap_err();
        assert_eq!(err, WitnessAbiCode::Blake3Mismatch);
    }

    #[test]
    fn native_path_rejects_empty_input() {
        let blake3 = [0; 32];
        let err = witness_generator_native::<ToyGenerator>(&[], &blake3, &blake3).unwrap_err();
        assert_eq!(err, WitnessAbiCode::MalformedInput);
    }

    #[test]
    fn native_path_rejects_postcard_garbage() {
        let blake3 = [0; 32];
        // Garbage bytes too short to be valid postcard for ToyInput.
        let err = witness_generator_native::<ToyGenerator>(&[0xff], &blake3, &blake3).unwrap_err();
        assert_eq!(err, WitnessAbiCode::PostcardDecodeError);
    }
}
