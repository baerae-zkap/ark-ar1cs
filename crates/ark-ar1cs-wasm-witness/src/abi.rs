//! Wasm ABI primitives and runtime helpers consumed by
//! [`crate::export_witness_generator`].
//!
//! Splitting the unsafe pointer/allocator code out of the macro keeps the
//! generated code minimal — the macro just hands typed arguments to typed
//! helpers in this module.

use alloc::alloc::{alloc, dealloc, Layout};
use alloc::vec::Vec;
use core::ptr;

/// Status codes returned across the wasm ABI boundary.
///
/// The numeric values are part of the contract — host code matches on these
/// integers via `WitnessAbiCode::try_from`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessAbiCode {
    Ok = 0,
    /// `input_len == 0` or `input_ptr` was null.
    MalformedInput = 1,
    /// `host_blake3_ptr` was null or did not match the embedded blake3.
    Blake3Mismatch = 5,
    /// `postcard::from_bytes::<Input>` failed.
    PostcardDecodeError = 6,
    /// `build_circuit` or `circuit_to_arwtns` returned an error.
    CircuitBuildError = 7,
    /// `wasm_alloc` could not satisfy the requested size.
    AllocError = 8,
}

impl WitnessAbiCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for WitnessAbiCode {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, i32> {
        match value {
            0 => Ok(WitnessAbiCode::Ok),
            1 => Ok(WitnessAbiCode::MalformedInput),
            5 => Ok(WitnessAbiCode::Blake3Mismatch),
            6 => Ok(WitnessAbiCode::PostcardDecodeError),
            7 => Ok(WitnessAbiCode::CircuitBuildError),
            8 => Ok(WitnessAbiCode::AllocError),
            other => Err(other),
        }
    }
}

/// Layout used by `wasm_alloc` / `wasm_free`.
///
/// The host MUST pair every successful allocation with `wasm_free(ptr, size)`
/// using the same `size` it received from the wasm side. The layout is
/// `(size, align=1)` because the buffers we hand back hold serialized bytes
/// (no field-element alignment requirements survive serialization).
fn buffer_layout(size: usize) -> Option<Layout> {
    Layout::from_size_align(size.max(1), 1).ok()
}

/// Allocate `size` bytes inside the wasm linear memory and return a raw
/// pointer the host can write into.
///
/// Returns null on overflow or allocation failure.
#[allow(clippy::missing_safety_doc)]
pub fn wasm_alloc_impl(size: u32) -> *mut u8 {
    let size = size as usize;
    let Some(layout) = buffer_layout(size) else {
        return ptr::null_mut();
    };
    // SAFETY: layout has size >= 1 and valid alignment.
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return ptr::null_mut();
    }
    ptr
}

/// Free a buffer previously returned by [`wasm_alloc_impl`].
///
/// # Safety
///
/// `ptr` MUST be a pointer returned by `wasm_alloc_impl` (or by an internal
/// helper that allocated through `buffer_layout`) and `size` MUST equal the
/// originally requested size. Passing any other pair is undefined behavior.
pub unsafe fn wasm_free_impl(ptr: *mut u8, size: u32) {
    if ptr.is_null() {
        return;
    }
    let size = size as usize;
    let Some(layout) = buffer_layout(size) else {
        return;
    };
    // SAFETY: contract delegated to caller.
    unsafe { dealloc(ptr, layout) };
}

/// Copy `bytes` into a freshly-allocated wasm buffer and write its
/// `(ptr, len)` to the host-provided out-pointers.
///
/// On allocation failure, both out-pointers are left untouched and the
/// function returns [`WitnessAbiCode::AllocError`].
///
/// # Safety
///
/// `out_ptr_out` and `out_len_out` must be valid, aligned, writable pointers
/// owned by the host (typically stack slots passed in via the call).
pub unsafe fn return_owned_buffer(
    bytes: &[u8],
    out_ptr_out: *mut *mut u8,
    out_len_out: *mut u32,
) -> WitnessAbiCode {
    let len = bytes.len();
    if len > u32::MAX as usize {
        return WitnessAbiCode::AllocError;
    }
    let buf_ptr = wasm_alloc_impl(len as u32);
    if buf_ptr.is_null() {
        return WitnessAbiCode::AllocError;
    }
    // SAFETY: buf_ptr is non-null, points to `len` writable bytes; bytes is a
    // valid slice of the same length.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, len);
        ptr::write(out_ptr_out, buf_ptr);
        ptr::write(out_len_out, len as u32);
    }
    WitnessAbiCode::Ok
}

/// Compare a host-provided 32-byte blake3 against the embedded constant.
///
/// Returns `Ok` on match, `Blake3Mismatch` otherwise (including when
/// `host_blake3_ptr` is null).
///
/// # Safety
///
/// If non-null, `host_blake3_ptr` must point to at least 32 readable bytes.
pub unsafe fn check_host_blake3(
    host_blake3_ptr: *const u8,
    embedded: &[u8; 32],
) -> WitnessAbiCode {
    if host_blake3_ptr.is_null() {
        return WitnessAbiCode::Blake3Mismatch;
    }
    // SAFETY: caller guarantees 32 readable bytes.
    let host = unsafe { core::slice::from_raw_parts(host_blake3_ptr, 32) };
    if host == embedded.as_slice() {
        WitnessAbiCode::Ok
    } else {
        WitnessAbiCode::Blake3Mismatch
    }
}

/// Borrow the host-provided postcard input slice.
///
/// Returns `Err(MalformedInput)` if the pointer is null or the length is
/// zero.
///
/// # Safety
///
/// If non-null, `input_ptr` must point to `input_len` readable bytes.
pub unsafe fn borrow_input<'a>(
    input_ptr: *const u8,
    input_len: u32,
) -> Result<&'a [u8], WitnessAbiCode> {
    if input_ptr.is_null() || input_len == 0 {
        return Err(WitnessAbiCode::MalformedInput);
    }
    // SAFETY: caller guarantees `input_len` readable bytes.
    Ok(unsafe { core::slice::from_raw_parts(input_ptr, input_len as usize) })
}

/// Serialize `arwtns` into a `Vec<u8>` and forward it to
/// [`return_owned_buffer`].
///
/// Centralizes the "ArwtnsFile → bytes → host buffer" pipeline so the macro
/// stays one statement long.
///
/// # Safety
///
/// Same contract as [`return_owned_buffer`].
pub unsafe fn return_arwtns<F: ark_ff::PrimeField>(
    arwtns: &ark_ar1cs_wtns::ArwtnsFile<F>,
    out_ptr_out: *mut *mut u8,
    out_len_out: *mut u32,
) -> WitnessAbiCode {
    let mut buf: Vec<u8> = Vec::new();
    if arwtns.write(&mut buf).is_err() {
        return WitnessAbiCode::CircuitBuildError;
    }
    // SAFETY: contract delegated to caller.
    unsafe { return_owned_buffer(&buf, out_ptr_out, out_len_out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_roundtrip() {
        let p = wasm_alloc_impl(64);
        assert!(!p.is_null());
        // SAFETY: paired with the alloc above.
        unsafe { wasm_free_impl(p, 64) };
    }

    #[test]
    fn alloc_zero_size_yields_nonnull() {
        let p = wasm_alloc_impl(0);
        assert!(!p.is_null());
        // SAFETY: paired with the alloc above.
        unsafe { wasm_free_impl(p, 0) };
    }

    #[test]
    fn return_owned_buffer_writes_outparams() {
        let payload = b"hello-arwtns";
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: u32 = 0;
        // SAFETY: out_ptr/out_len are stack-owned and writable.
        let code = unsafe {
            return_owned_buffer(payload, &mut out_ptr as *mut *mut u8, &mut out_len as *mut u32)
        };
        assert_eq!(code, WitnessAbiCode::Ok);
        assert_eq!(out_len as usize, payload.len());
        // SAFETY: pointer + len are exactly what we just wrote.
        let slice = unsafe { core::slice::from_raw_parts(out_ptr, out_len as usize) };
        assert_eq!(slice, payload);
        // SAFETY: paired with the alloc inside return_owned_buffer.
        unsafe { wasm_free_impl(out_ptr, out_len) };
    }

    #[test]
    fn check_host_blake3_match_and_mismatch() {
        let embedded = [7u8; 32];
        // SAFETY: pointing to a stack-owned 32-byte array.
        let ok = unsafe { check_host_blake3(embedded.as_ptr(), &embedded) };
        assert_eq!(ok, WitnessAbiCode::Ok);

        let other = [9u8; 32];
        // SAFETY: pointing to a stack-owned 32-byte array.
        let mis = unsafe { check_host_blake3(other.as_ptr(), &embedded) };
        assert_eq!(mis, WitnessAbiCode::Blake3Mismatch);

        // SAFETY: explicitly null pointer; helper handles null path.
        let null = unsafe { check_host_blake3(core::ptr::null(), &embedded) };
        assert_eq!(null, WitnessAbiCode::Blake3Mismatch);
    }

    #[test]
    fn borrow_input_rejects_null_or_empty() {
        // SAFETY: null pointer path; helper handles it.
        let null = unsafe { borrow_input(core::ptr::null(), 4) };
        assert_eq!(null.unwrap_err(), WitnessAbiCode::MalformedInput);

        let bytes = [1u8, 2, 3];
        // SAFETY: empty length forces the early-return path.
        let empty = unsafe { borrow_input(bytes.as_ptr(), 0) };
        assert_eq!(empty.unwrap_err(), WitnessAbiCode::MalformedInput);

        // SAFETY: pointer + len match a valid stack slice.
        let ok = unsafe { borrow_input(bytes.as_ptr(), bytes.len() as u32) };
        assert_eq!(ok.unwrap(), &bytes[..]);
    }

    #[test]
    fn abi_codes_round_trip_via_try_from() {
        for code in [
            WitnessAbiCode::Ok,
            WitnessAbiCode::MalformedInput,
            WitnessAbiCode::Blake3Mismatch,
            WitnessAbiCode::PostcardDecodeError,
            WitnessAbiCode::CircuitBuildError,
            WitnessAbiCode::AllocError,
        ] {
            assert_eq!(WitnessAbiCode::try_from(code.as_i32()).unwrap(), code);
        }
        assert!(WitnessAbiCode::try_from(99).is_err());
    }
}
