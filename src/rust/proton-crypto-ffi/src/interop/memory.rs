//! Allocation helpers for byte buffers and strings handed to the host, and the exported
//! [`interop_memory_free`] the host releases them with.

use std::ffi::c_void;
use std::ptr;

pub fn malloc_c_string(data: &[u8]) -> *mut u8 {
    // Allocate for the string length + null terminating byte.
    let len = data.len().saturating_add(1);
    let ptr = unsafe { libc::malloc(len).cast::<u8>() };
    if ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        ptr.copy_from_nonoverlapping(data.as_ptr(), data.len());
        // Add the null terminating byte.
        *ptr.add(data.len()) = 0;
    }

    ptr
}

/// Byte buffer allocated for the host to read (UTF-8 or opaque). Frees with [`interop_memory_free`].
///
/// An empty `data` yields `Ok(null)` (the caller pairs it with a zero length). A non-empty `data`
/// whose allocation fails returns `Err` rather than a null pointer, so the host never sees a null
/// pointer paired with a non-zero length.
pub fn malloc_bytes(data: &[u8]) -> Result<*mut u8, String> {
    if data.is_empty() {
        return Ok(ptr::null_mut());
    }

    let ptr = unsafe { libc::malloc(data.len()).cast::<u8>() };
    if ptr.is_null() {
        return Err("failed to allocate buffer for host transfer".to_string());
    }

    unsafe {
        ptr.copy_from_nonoverlapping(data.as_ptr(), data.len());
    }

    Ok(ptr)
}

/// Copies `src` into the caller-provided `(dst, dst_len)` buffer, failing with
/// "`what` buffer too small" if it doesn't fit.
///
/// # Safety
/// When `src` is non-empty, `dst` must be writable for `dst_len` bytes.
pub fn copy_to_host_buffer(
    src: &[u8],
    dst: *mut u8,
    dst_len: usize,
    what: &str,
) -> Result<(), String> {
    if src.len() > dst_len {
        return Err(format!("{what} buffer too small"));
    }
    if !src.is_empty() {
        if dst.is_null() {
            return Err(format!("{what} buffer is null"));
        }
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
    }
    Ok(())
}

/// Frees a buffer or string this crate returned through its FFI allocation helpers.
///
/// Releases pointers produced by the malloc-based helpers (for example [`malloc_bytes`] and
/// [`malloc_c_string`]), including buffers returned via `*mut *mut u8` out-params and owned
/// `InteropError` messages. Implemented on the platform C heap to match managed interop callers.
/// A null `ptr` is a no-op.
///
/// # Safety
/// `ptr` must be either null or a pointer previously returned by one of this crate's malloc-based
/// helpers and not yet freed; after this call the pointer must not be used or freed again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interop_memory_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            libc::free(ptr);
        }
    }
}
